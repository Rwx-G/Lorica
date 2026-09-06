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
//! Shared by both startup modes: the follower runtime lives in the
//! supervisor (or the single process); workers never dial.

use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use lorica_api::cluster::FollowerRuntime;
use lorica_api::db::db_blocking;
use lorica_api::error::ApiError;
use lorica_cluster::messages::{cluster_response, Renew};
use lorica_cluster::{ClusterRequest, Dialer, DialerConfig, DialerHandle};
use lorica_config::models::ClusterIdentity;
use lorica_config::store::ConfigStore;
use tokio::sync::{watch, Mutex};
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

/// How often the renewal task checks the certificate's remaining
/// lifetime.
const RENEWAL_CHECK_INTERVAL: Duration = Duration::from_secs(600);

/// Renew when this much of the 90-day lifetime is left (a third:
/// AC #12's "two thirds of lifetime").
const RENEWAL_LEAD: chrono::Duration = chrono::Duration::days(30);

/// Bound on one renewal exchange.
const RENEWAL_TIMEOUT: Duration = Duration::from_secs(15);

/// Inputs for [`spawn_follower`].
pub(crate) struct FollowerOptions {
    /// Whether this process also runs a control plane (`--cluster-listen`).
    /// A node cannot be both; the control-plane path refuses first,
    /// this is the belt to its braces.
    pub is_control_plane: bool,
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

/// Start the follower runtime when a fleet identity exists.
/// `Ok(None)` on a node that never joined.
pub(crate) async fn spawn_follower(
    opts: FollowerOptions,
    store: &Arc<Mutex<ConfigStore>>,
) -> Result<Option<FollowerPlane>, String> {
    let (identity, schema_version) = {
        let store = store.lock().await;
        let identity = store
            .get_cluster_identity()
            .map_err(|e| format!("follower: failed to read the fleet identity: {e}"))?;
        let schema = store
            .schema_version()
            .map_err(|e| format!("follower: failed to read the schema version: {e}"))?;
        (identity, schema)
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

    let mut config = DialerConfig::new(
        &identity.control_plane,
        &identity.server_name,
        &identity.ca_pem,
        &identity.cert_pem,
        &identity.key_pem,
        u32::try_from(schema_version).unwrap_or(u32::MAX),
    )
    .with_node_name(&identity.node_name);
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

    // Renewal task (AC #12).
    let renew_dialer = Arc::clone(&dialer);
    let renew_store = Arc::clone(store);
    let renew_connection = connection;
    let renewal_task = tokio::spawn(async move {
        loop {
            tokio::time::sleep(RENEWAL_CHECK_INTERVAL).await;
            let current = db_blocking(&renew_store, |store| {
                store.get_cluster_identity().map_err(internal)
            })
            .await;
            let Ok(Some(current)) = current else {
                continue;
            };
            if Utc::now() + RENEWAL_LEAD < current.cert_not_after {
                continue;
            }
            let Some(session) = renew_connection.current() else {
                warn!("follower: certificate renewal due but the control plane is unreachable; will retry");
                continue;
            };
            match renew_once(&session.endpoint, &current, &renew_store).await {
                Ok((cert_pem, key_pem, not_after)) => {
                    let swapped = renew_dialer
                        .lock()
                        .unwrap_or_else(|p| p.into_inner())
                        .as_ref()
                        .map(|d| d.update_identity(&cert_pem, &key_pem));
                    match swapped {
                        Some(Ok(())) => info!(
                            not_after = %not_after.to_rfc3339(),
                            "follower: node certificate renewed; the next connection presents it"
                        ),
                        Some(Err(e)) => error!(error = %e, "follower: renewed identity rejected by the dialer"),
                        None => {}
                    }
                }
                Err(e) => warn!(error = %e, "follower: certificate renewal failed; will retry"),
            }
        }
    });

    warn!(
        node_id = %identity.node_id,
        node_name = %identity.node_name,
        control_plane = %identity.control_plane,
        cert_not_after = %identity.cert_not_after.to_rfc3339(),
        "follower mode: dialing the control plane"
    );
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
