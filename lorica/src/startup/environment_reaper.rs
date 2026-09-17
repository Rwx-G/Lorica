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

//! The environment reaper (Story 10.4 AC #7): the sweep that removes
//! environments past their `expires_at`.
//!
//! It runs on a standalone node or a control plane and never on a
//! follower. A follower's configuration is replaced by replication;
//! a delete it performed locally would be undone on the next round,
//! and the control plane's own sweep removes the rows for the whole
//! fleet. The gate is checked twice: at spawn, on the fleet role the
//! process started with, and at every tick, on the stored identity,
//! so a node that joins a fleet after boot stops sweeping without a
//! restart. Both checks answer to `ConfigStore::is_follower`, which
//! owns the one fail-closed disposition a read failure gets.
//!
//! The sweep itself lives in `lorica_api::automation`, beside the
//! `DELETE` handler, so both remove exactly the same rows in the same
//! transaction. What lives here is the ticker, the role gate and the
//! reload signal a non-empty sweep owes the proxy.

use std::sync::Arc;
use std::time::Duration;

use lorica_api::cluster::ClusterRuntime;
use lorica_api::db::db_blocking;
use lorica_api::error::ApiError;
use lorica_config::ConfigStore;
use tokio::sync::{watch, Mutex};
use tokio_util::task::TaskTracker;
use tracing::{info, warn};

/// How often the reaper sweeps. AC #7 says every minute; the TTL a
/// pipeline asks for is measured in hours, so a minute of lag on the
/// removal is invisible to it and cheap for the store.
pub const ENVIRONMENT_REAPER_INTERVAL: Duration = Duration::from_secs(60);

/// Spawn the reaper, or return `None` on a follower.
///
/// `config_reload` is bumped after a sweep that removed something, so
/// the proxy drops the routes and, on a control plane, the fleet gets
/// the generation without them.
pub fn spawn_environment_reaper(
    cluster: &ClusterRuntime,
    store: Arc<Mutex<ConfigStore>>,
    log_store: Option<Arc<lorica_api::log_store::LogStore>>,
    config_reload: watch::Sender<u64>,
    tracker: &TaskTracker,
    interval: Duration,
) -> Option<tokio::task::JoinHandle<()>> {
    if matches!(cluster, ClusterRuntime::Follower(_)) {
        info!("environment reaper not started: this node is a follower");
        return None;
    }
    Some(tracker.spawn(async move {
        let mut ticker = tokio::time::interval(interval);
        ticker.tick().await; // skip the immediate tick
        loop {
            ticker.tick().await;
            if is_follower_now(&store).await {
                continue;
            }
            let reaped = lorica_api::automation::reap_expired_environments(
                &store,
                log_store.clone(),
                chrono::Utc::now(),
            )
            .await;
            if reaped.is_empty() {
                continue;
            }
            info!(
                count = reaped.len(),
                "environment reaper removed expired environments"
            );
            let next = *config_reload.borrow() + 1;
            let _ = config_reload.send(next);
        }
    }))
}

/// Whether the store now holds a follower identity, read off the
/// blocking pool.
///
/// The disposition on a read failure belongs to
/// [`ConfigStore::is_follower`], not here: every caller of that
/// helper answers a read failure with "follower", so a sweep that
/// invented its own answer would be the fourth disposition the audit
/// counted.
///
/// The read itself goes through [`db_blocking`] because a SQLite
/// query is blocking work: run inline under `store.lock().await` it
/// parks a runtime worker thread, which is what every sibling sweep
/// in this crate already avoids. A join failure is the only error
/// this can return, and it fails closed for the same reason.
async fn is_follower_now(store: &Arc<Mutex<ConfigStore>>) -> bool {
    db_blocking(store, |store| {
        Ok::<bool, ApiError>(store.is_follower())
    })
    .await
    .unwrap_or_else(|e| {
        warn!(error = %e, "environment reaper could not read the fleet identity; skipping this sweep");
        true
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use lorica_config::models::ClusterIdentity;

    #[tokio::test]
    async fn a_stored_follower_identity_stops_the_sweep() {
        let store = ConfigStore::open_in_memory().expect("test store opens");
        let store = Arc::new(Mutex::new(store));
        assert!(!is_follower_now(&store).await);

        let now = chrono::Utc::now();
        store
            .lock()
            .await
            .set_cluster_identity(&ClusterIdentity {
                node_id: "00000000-0000-4000-8000-000000000001".to_string(),
                node_name: "follower01".to_string(),
                cert_pem: String::new(),
                key_pem: String::new(),
                ca_pem: String::new(),
                control_plane: "cp.internal:9444".to_string(),
                server_name: "cp.internal".to_string(),
                enrolled_at: now,
                cert_not_after: now + chrono::Duration::days(90),
            })
            .expect("identity write");
        assert!(is_follower_now(&store).await);
    }

    #[tokio::test]
    async fn a_standalone_node_spawns_the_reaper() {
        let store = Arc::new(Mutex::new(
            ConfigStore::open_in_memory().expect("test store opens"),
        ));
        let (tx, _rx) = watch::channel(0u64);
        let tracker = TaskTracker::new();
        let handle = spawn_environment_reaper(
            &ClusterRuntime::Standalone,
            store,
            None,
            tx,
            &tracker,
            Duration::from_secs(3600),
        );
        assert!(handle.is_some());
        handle.expect("spawned").abort();
    }
}
