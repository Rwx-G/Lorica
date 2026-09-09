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
    AppliedConfig, CertBundle, CertInstallReport, ClusterRequest, ConfigPayload, ConfigVersion,
    Dialer, DialerConfig, DialerHandle, FollowerHandler, SessionHandle, MAX_CERT_PULL_IDS,
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

/// How often a follower checks whether it is missing certificate keys
/// and asks for them (Story 9.5 AC #8).
///
/// Short, because the window it closes is a hostname served by the
/// default certificate: a renewal whose key did not arrive leaves the
/// node functional but wrong, and every interval is time a client
/// spends getting the wrong certificate. Cheap too, since the check
/// short-circuits on an empty result without touching the session.
const KEY_RECONCILE_INTERVAL: Duration = Duration::from_secs(60);

/// How this process reaches its data-plane ban map (Story 9.6 AC #10).
///
/// Two shapes because the two process modes genuinely differ, and both
/// already exist for the local ban paths: single-process holds the
/// shared map, supervisor mode broadcasts a `BanIp` command to every
/// worker. Reusing the existing mechanisms means a fleet-wide ban and
/// a local one land the same way and are visible in the same place.
/// One type for both directions, because a mode that can apply a ban
/// is exactly the mode that can read them back: splitting them into
/// two enums produced two parallel matches that could disagree about
/// which mode this process is in.
#[derive(Clone)]
pub(crate) enum BanApplier {
    /// Single-process: the shared data-plane map, read and written
    /// directly.
    Direct(Arc<lorica_api::ban::BanMap>),
    /// Supervisor mode: the map lives in each worker. Writes go out on
    /// the same broadcast the local WAF auto-ban uses; reads come from
    /// what the workers already report, which is the same source
    /// `GET /api/v1/bans` uses, so the fleet view and the local view
    /// cannot disagree.
    Workers {
        /// `(ip, duration_s, reason)` to every per-worker task.
        broadcast: tokio::sync::broadcast::Sender<(String, u64, i32)>,
        /// The per-worker reports, already merged.
        reports: Arc<lorica_api::workers::AggregatedMetrics>,
    },
}

impl BanApplier {
    /// The bans live on this node right now, bounded, as the wire
    /// wants them (Story 9.6 AC #10).
    ///
    /// Bans have no table (decision D3): they are an in-memory map
    /// rebuilt from nothing on restart, so this is a snapshot for
    /// visibility and is lossy across a restart by construction.
    pub(crate) async fn snapshot(&self) -> Vec<lorica_cluster::TelemetryBan> {
        match self {
            Self::Direct(map) => map
                .iter()
                .filter_map(|entry| {
                    let record = entry.value();
                    let elapsed = record.banned_at.elapsed().as_secs();
                    // An entry past its duration has not been reaped
                    // yet; it is not a ban and must not show as one.
                    (elapsed < record.duration_s).then(|| lorica_cluster::TelemetryBan {
                        client_ip: entry.key().clone(),
                        remaining_s: record.duration_s - elapsed,
                        reason: record.reason.as_str().to_string(),
                    })
                })
                .take(lorica_cluster::MAX_TELEMETRY_BANS)
                .collect(),
            Self::Workers { reports, .. } => reports
                .merged_ban_list()
                .await
                .into_iter()
                .map(
                    |(client_ip, remaining_s, _duration, reason)| lorica_cluster::TelemetryBan {
                        client_ip,
                        remaining_s,
                        reason: reason.as_str().to_string(),
                    },
                )
                .take(lorica_cluster::MAX_TELEMETRY_BANS)
                .collect(),
        }
    }
}

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
    /// How to apply a fleet-wide ban locally (Story 9.6 AC #10).
    pub bans: BanApplier,
    /// The data directory, whose filesystem is the one the heartbeat
    /// reports on (Story 9.7 AC #3). Not the root filesystem: what
    /// fills up on a proxy is where its logs and databases live.
    pub data_dir: std::path::PathBuf,
}

/// Live handles for a running follower.
pub(crate) struct FollowerPlane {
    /// The handle the management API reads (status, leave).
    pub runtime: Arc<FollowerRuntime>,
    /// The dialer, shared with the leave watcher and the renewal task
    /// (both need to reach it after spawn).
    dialer: Arc<std::sync::Mutex<Option<DialerHandle>>>,
    tasks: Vec<JoinHandle<()>>,
    /// Tasks adopted after construction; see [`FollowerPlane::watch`].
    extra: StdMutex<Vec<JoinHandle<()>>>,
}

impl FollowerPlane {
    /// Adopt a task that must stop when this plane does.
    ///
    /// The telemetry drain is spawned after the plane exists (it
    /// needs the runtime handle), so it cannot be in `tasks` at
    /// construction; handing it over here keeps `shutdown` the single
    /// place that stops everything.
    pub fn watch(&self, task: JoinHandle<()>) {
        self.extra
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .push(task);
    }

    /// Stop dialing and the background tasks.
    pub fn shutdown(self) {
        for task in self.tasks {
            task.abort();
        }
        for task in self
            .extra
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .drain(..)
        {
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
    /// The dialer's connection slot, set once right after the dialer
    /// spawns. It is a `OnceLock` because of a construction cycle: the
    /// dialer needs this handler, and this handler needs the slot the
    /// dialer creates.
    ///
    /// Without it the key reconciliation could only run from inside a
    /// request the control plane initiated, which is precisely the bug
    /// that made AC #8 conditional.
    connection: std::sync::OnceLock<lorica_cluster::ClusterConnection>,
    /// How a fleet-wide ban reaches this node's data plane.
    bans: BanApplier,
    /// `(generation, phase)` pairs already alerted on, so a generation
    /// this node cannot take raises one alert instead of one per
    /// heartbeat. Bounded by the number of generations this process
    /// refuses, which an operator fixing the configuration ends; a node
    /// refusing thousands of distinct generations has a louder problem
    /// than this map.
    alerted: StdMutex<HashSet<(u64, String)>>,
    /// The sampler behind the heartbeat's gauges (Story 9.7 AC #3).
    ///
    /// Owned here rather than shared with the management API's cache:
    /// that one is refreshed by operator requests, which on a follower
    /// may never come, and a gauge nobody refreshes is worse than no
    /// gauge. Refreshing it costs a few milliseconds once per
    /// heartbeat interval.
    sampler: StdMutex<lorica_api::system::SystemCache>,
    /// The filesystem the disk gauge reports on.
    data_dir: std::path::PathBuf,
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
        // `session` is kept for the certificate pull at the end: the
        // connection is already open and authenticated, so the keys
        // ride the same round trip budget as the configuration.

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

    /// Install certificate material the control plane sent (Story 9.5
    /// AC #7/#8), verifying each key against the digest that travelled
    /// with it before writing anything.
    ///
    /// A bundle whose certificate row does not exist yet is REFUSED
    /// rather than created: the row is the configuration's business,
    /// and a key without one means the push overtook the generation
    /// that introduces it. That resolves itself, because the follower
    /// asks again after its next apply, when the row exists and it can
    /// see exactly what it still lacks.
    async fn install_certs(&self, bundles: Vec<CertBundle>) -> CertInstallReport {
        let mut report = CertInstallReport::default();
        for bundle in bundles {
            // Computed with the SAME function the canonical blob uses,
            // so this check cannot pass here and fail there.
            //
            // What it proves and what it does not: both the key and the
            // digest arrived in the same message from the same sender,
            // so this detects corruption in transit, NOT a disagreement
            // between the key channel and the configuration channel.
            // Proving that would need the digest the blob announced,
            // and the replica apply does not keep it.
            let computed = lorica_config::canonical::secret_digest(&bundle.key_pem);
            if computed != bundle.key_digest {
                report.refused.push((
                    bundle.cert_id.clone(),
                    "key does not match the digest it arrived with".to_string(),
                ));
                continue;
            }
            let cert_id = bundle.cert_id.clone();
            let installed = db_blocking(&self.store, move |store| {
                let existing = match store.get_certificate(&bundle.cert_id) {
                    Ok(Some(existing)) => existing,
                    Ok(None) => {
                        return Ok::<_, ApiError>(Err(
                            "no certificate row for this id yet".to_string()
                        ))
                    }
                    Err(e) => return Ok(Err(e.to_string())),
                };
                let row = lorica_config::models::Certificate {
                    cert_pem: bundle.cert_pem,
                    key_pem: bundle.key_pem,
                    ..existing
                };
                match store.update_certificate(&row) {
                    // Encryption at rest happens on write, under THIS
                    // node's master key, which is all AC #2 means by
                    // re-encrypting under the follower's own key. There
                    // is no second crypto path.
                    Ok(()) => Ok(Ok(row)),
                    Err(e) => Ok(Err(e.to_string())),
                }
            })
            .await;
            match installed {
                Ok(Ok(row)) => {
                    self.export_installed(row).await;
                    report.installed.push(cert_id);
                }
                Ok(Err(reason)) => report.refused.push((cert_id, reason)),
                Err(e) => report.refused.push((cert_id, e.to_string())),
            }
        }
        if !report.installed.is_empty() {
            info!(
                installed = report.installed.len(),
                refused = report.refused.len(),
                "installed certificate keys from the control plane"
            );
            lorica_api::metrics::inc_cluster_cert_push_by(
                &self.node_id,
                "installed",
                report.installed.len(),
            );
            // The resolver reads keys at reload, and until now these
            // certificates were being skipped for having none.
            self.config_reload
                .send_modify(|seq| *seq = seq.wrapping_add(1));
        }
        for (cert_id, reason) in &report.refused {
            warn!(cert_id, %reason, "refused a certificate the control plane sent");
            lorica_api::metrics::inc_cluster_cert_push(&self.node_id, "refused");
        }
        report
    }

    /// Write a newly-installed certificate to the filesystem export
    /// zone (Story 9.5 AC #9, decision D8).
    ///
    /// Triggered HERE and not from the configuration apply, because at
    /// apply time a certificate this node has no key for would export
    /// an empty private-key file. By the time this runs the key is
    /// present and verified. The zone itself is node-local settings,
    /// which never replicate; only the ACL rows do.
    async fn export_installed(&self, cert: lorica_config::models::Certificate) {
        let inputs = db_blocking(&self.store, |store| {
            Ok::<_, ApiError>(lorica_api::cert_export::snapshot_export_inputs(store))
        })
        .await;
        if let Ok(Some((settings, acls))) = inputs {
            lorica_api::cert_export::export_after_release(settings, acls, cert).await;
        }
    }

    /// Reconcile this node's certificate keys with the control plane
    /// (AC #8).
    ///
    /// # Why this is a reconciler and not a step of the apply
    ///
    /// It was originally chained to the end of a configuration pull,
    /// which made it unreachable on the ordinary path: a node that a
    /// push brought up to date is by definition NOT behind, so the
    /// pull that carried the chained request never ran again. A node
    /// could sit indefinitely holding a certificate row with no key,
    /// serving the default certificate, with nothing left to ask.
    ///
    /// Configuration has a reconciler, the version comparison on every
    /// heartbeat. Keys need their own, driven by what the node is
    /// missing rather than by what generation it is on.
    ///
    /// # Why break-glass does not gate this
    ///
    /// A key overwrites no operator edit (D9). Gating it was the same
    /// mistake in a second place: it would let a certificate expire in
    /// the middle of the incident the window was opened for, which is
    /// exactly what D9 exists to prevent.
    async fn reconcile_keys(&self) {
        let Some(connection) = self.connection.get() else {
            return;
        };
        let Some(session) = connection.current() else {
            return;
        };
        self.pull_missing_certs(&session).await;
    }

    /// Ask the control plane for the keys this node is missing (AC #8).
    ///
    /// Called after an apply, which is exactly when the node knows what
    /// it lacks: the apply just counted the certificates it wrote
    /// without a key. This is the path that carries the guarantee; the
    /// control plane's push is the latency optimisation on top of it
    /// (decision D2).
    async fn pull_missing_certs(&self, session: &SessionHandle) {
        let missing = db_blocking(&self.store, |store| {
            let ids: Vec<String> = store
                .list_certificates()
                .map_err(internal)?
                .into_iter()
                .filter(|c| c.key_pem.is_empty())
                .map(|c| c.id)
                .take(MAX_CERT_PULL_IDS)
                .collect();
            Ok::<_, ApiError>(ids)
        })
        .await;
        let Ok(missing) = missing else {
            return;
        };
        if missing.is_empty() {
            return;
        }
        info!(
            missing = missing.len(),
            "asking the control plane for certificate keys this node lacks"
        );
        let response = tokio::time::timeout(
            PULL_TIMEOUT,
            session.endpoint.request(
                ClusterRequest::cert_pull(lorica_cluster::messages::CertPull { cert_ids: missing }),
                PULL_TIMEOUT,
            ),
        )
        .await;
        let bundles = match response {
            Ok(Ok(response)) => match response.body {
                Some(cluster_response::Body::CertPullAck(ack)) => ack.bundles,
                _ => {
                    warn!(
                        status = ?response.cluster_status(),
                        "control plane refused the certificate pull"
                    );
                    return;
                }
            },
            Ok(Err(e)) => {
                warn!(error = %e, "certificate pull failed; retrying after the next apply");
                return;
            }
            Err(_) => {
                warn!("certificate pull timed out; retrying after the next apply");
                return;
            }
        };
        if bundles.is_empty() {
            // Entitlement is the control plane's call, so an empty
            // answer is a legitimate "you are not selected for these",
            // not a failure. Saying so once beats a silent no-op.
            info!("control plane sent no keys: this node is selected for none of them");
            return;
        }
        let bundles: Vec<CertBundle> = bundles.into_iter().map(CertBundle::from_material).collect();
        // `install_certs` counts what was installed and what was
        // refused; counting the pull here too would book the same
        // certificates twice under this node id.
        let report = self.install_certs(bundles).await;
        info!(
            installed = report.installed.len(),
            refused = report.refused.len(),
            "certificate pull complete"
        );
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

    fn resources(&self) -> Option<lorica_cluster::NodeResources> {
        let mut sampler = self.sampler.lock().unwrap_or_else(|p| p.into_inner());
        sampler.refresh();
        // `disk_usage_statvfs` returns `None` on a path it cannot
        // stat, which is a reason to report zero for the disk pair
        // rather than to withhold the CPU and memory readings that
        // did work: the dashboard renders a zero total as unknown.
        let disk = lorica_api::system::disk_usage_statvfs(&self.data_dir, "data");
        Some(lorica_cluster::NodeResources {
            // Rounded to whole percent on the sender, so the wire
            // carries the same figure the gauge shows and nothing
            // downstream has to decide how to round it.
            cpu_percent: sampler.cpu_usage_percent().round().clamp(0.0, 100.0) as u32,
            memory_used_bytes: sampler.memory_used_bytes(),
            memory_total_bytes: sampler.memory_total_bytes(),
            disk_used_bytes: disk.as_ref().map(|d| d.used_bytes).unwrap_or(0),
            disk_total_bytes: disk.as_ref().map(|d| d.total_bytes).unwrap_or(0),
        })
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
        // Reconciliation is NOT chained here on purpose. The commit ack
        // is on the control plane's per-node deadline, and a key pull
        // is a second round trip on the same session; the periodic
        // reconciler picks it up within its interval instead. Chaining
        // it would put an unrelated exchange inside the budget the
        // coordinator measures.
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

    fn on_challenge_publish(
        &self,
        identifier: String,
        token: String,
        key_authorization: String,
    ) -> BoxFuture<'_, Result<(), String>> {
        Box::pin(async move {
            // The deadline is stamped HERE, from this node's own clock,
            // which is why the message carries none: an absolute
            // instant chosen by the control plane would make a token's
            // validity depend on clock agreement between two machines,
            // and produce either tokens already expired on arrival or
            // tokens outliving their window.
            let expires_at = Utc::now() + lorica_api::acme::CHALLENGE_TTL;
            let written = db_blocking(&self.store, move |store| {
                store
                    .set_acme_challenge(&token, &key_authorization, expires_at)
                    .map_err(internal)
            })
            .await;
            match written {
                Ok(()) => {
                    info!(identifier, "published an HTTP-01 challenge for the control plane");
                    Ok(())
                }
                Err(e) => {
                    // Answering Err is what stops the order: the
                    // control plane refuses rather than telling the
                    // certificate authority to validate against a node
                    // that will answer 404.
                    error!(identifier, error = %e, "could not publish the HTTP-01 challenge");
                    Err(e.to_string())
                }
            }
        })
    }

    fn on_ban_push(
        &self,
        client_ip: String,
        duration_s: u64,
        reason: String,
    ) -> BoxFuture<'_, Result<bool, String>> {
        Box::pin(async move {
            // The reason travelled as text on the wire but the data
            // plane stores an enum, so an unknown one lands as a
            // manual ban rather than being mislabelled as an
            // automatic one: this arrived from an operator, whatever
            // string they used.
            let reason_code = match reason.as_str() {
                "rate_limit" => lorica_api::ban::BanReason::RateLimit,
                "waf_flood" => lorica_api::ban::BanReason::WafFlood,
                "waf_critical_rule" => lorica_api::ban::BanReason::WafCriticalRule,
                _ => lorica_api::ban::BanReason::Manual,
            };
            match &self.bans {
                BanApplier::Direct(map) => {
                    map.insert(
                        client_ip.clone(),
                        lorica_api::ban::BanRecord {
                            banned_at: std::time::Instant::now(),
                            duration_s,
                            reason: reason_code,
                        },
                    );
                    info!(client_ip = %client_ip, duration_s, "applied a fleet-wide ban");
                    Ok(true)
                }
                BanApplier::Workers { broadcast: tx, .. } => {
                    // A send with no subscribers is not an error: it
                    // means no worker is up right now, and a worker
                    // that starts later picks the ban up from the
                    // store on its next reload.
                    let applied = tx
                        .send((client_ip.clone(), duration_s, reason_code.as_i32()))
                        .is_ok();
                    info!(
                        client_ip = %client_ip,
                        duration_s,
                        applied,
                        "broadcast a fleet-wide ban to the workers"
                    );
                    Ok(applied)
                }
            }
        })
    }

    fn on_challenge_retract(&self, token: String) -> BoxFuture<'_, ()> {
        Box::pin(async move {
            let removed = db_blocking(&self.store, move |store| {
                store.delete_acme_challenge(&token).map_err(internal)
            })
            .await;
            if let Err(e) = removed {
                // Infallible by contract, like the driver cleanup it
                // mirrors. A miss now costs the entry its deadline
                // rather than leaking it, which is what the expiry
                // added by this story is for.
                warn!(error = %e, "could not retract an HTTP-01 challenge; it expires on its own");
            }
        })
    }

    fn on_cert_push(&self, bundles: Vec<CertBundle>) -> BoxFuture<'_, CertInstallReport> {
        // No break-glass check, deliberately (Story 9.5 D9): a private
        // key overwrites no operator edit, and freezing delivery for a
        // window of up to a day could expire a certificate during the
        // very incident the window was opened for.
        Box::pin(async move { self.install_certs(bundles).await })
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
        bans: opts.bans,
        alerted: StdMutex::new(HashSet::new()),
        connection: std::sync::OnceLock::new(),
        sampler: StdMutex::new(lorica_api::system::SystemCache::new()),
        data_dir: opts.data_dir,
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
    .with_follower(Arc::clone(&replica) as Arc<dyn FollowerHandler>);
    config.handshake = config
        .handshake
        .with_build_version(env!("CARGO_PKG_VERSION"));
    let dialer = Dialer::spawn(config).map_err(|e| format!("follower: dialer: {e}"))?;
    let connection = dialer.connection();
    // Close the construction cycle: the dialer owns the slot, and the
    // handler needs it to reconcile keys outside any request the
    // control plane initiated.
    let _ = replica.connection.set(connection.clone());
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

    // Key reconciliation (AC #8). Driven by what this node is missing,
    // never by what generation it is on, and deliberately outside the
    // break-glass gate.
    let reconcile_handler = Arc::clone(&replica);
    let key_reconciler = tokio::spawn(async move {
        loop {
            tokio::time::sleep(KEY_RECONCILE_INTERVAL).await;
            reconcile_handler.reconcile_keys().await;
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
        tasks: vec![leave_task, renewal_task, key_reconciler],
        extra: StdMutex::new(Vec::new()),
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
