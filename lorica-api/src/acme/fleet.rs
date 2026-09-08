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

//! Fleet-aware HTTP-01 challenge solving (Story 9.5 AC #6).
//!
//! # Why a wrapper and not a replacement
//!
//! [`AcmeChallengeStore`] already gets the local half right: it awaits
//! its own write, unwinds its cache when that write fails, and serves
//! every worker of this node from SQLite. This type adds exactly one
//! thing on top, the fan-out, and delegates the rest.
//!
//! # The verdict has to be all-or-nothing, and this is why
//!
//! A certificate authority chooses which node it validates against; we
//! do not. So the token has to be present on every node that could
//! answer for that hostname BEFORE the order is declared ready.
//! Declaring readiness while one node has nothing asks the authority
//! to validate against a machine that will answer 404, and what comes
//! back is an opaque "not ready" with no indication of which node
//! broke. Story 9.1 made `present` fallible precisely so this failure
//! can be named instead of guessed at.
//!
//! # Why an empty recipient set is NOT a refusal
//!
//! The local write always happens first, and the control plane serves
//! traffic like any other node. So "no follower resolved" legitimately
//! means "this hostname is served here", which is the single-node and
//! control-plane-only case. Refusing it would block issuance on a
//! perfectly ordinary fleet.
//!
//! What is worth saying out loud is the ambiguous case: a fleet that
//! HAS followers, for a hostname no route binds. Then the resolution
//! cannot tell whether the authority will reach this node or one that
//! holds no token, so the situation is logged at WARN rather than
//! silently accepted or silently refused.

use std::collections::HashMap;
use std::sync::{Arc, Mutex as StdMutex};

use lorica_acme::{AcmeError, Http01ChallengeSolver};
use lorica_config::ConfigStore;
use tokio::sync::Mutex;

use crate::acme::store::AcmeChallengeStore;
use crate::cluster::ClusterRuntime;

/// An HTTP-01 solver that publishes a token to this node and to every
/// follower that could answer for the hostname being validated.
pub struct FleetHttp01Solver {
    /// This node's own challenge store, written first and always.
    local: AcmeChallengeStore,
    /// The fleet role. Anything but a control plane behaves exactly
    /// like the local store alone.
    cluster: ClusterRuntime,
    /// Read to resolve which nodes could answer for a hostname.
    store: Arc<Mutex<ConfigStore>>,
    /// Which nodes took each live token, so the retraction reaches the
    /// same set. `cleanup` is given only a token, and re-resolving from
    /// the hostname would be wrong anyway: routes can change between
    /// publishing and retracting, and a token must be retracted from
    /// wherever it was actually put.
    delivered_to: StdMutex<HashMap<String, Vec<String>>>,
}

impl FleetHttp01Solver {
    /// Wrap a node's challenge store with fleet distribution.
    pub fn new(
        local: AcmeChallengeStore,
        cluster: ClusterRuntime,
        store: Arc<Mutex<ConfigStore>>,
    ) -> Self {
        Self {
            local,
            cluster,
            store,
            delivered_to: StdMutex::new(HashMap::new()),
        }
    }

    /// The nodes that could answer the authority for `identifier`.
    async fn recipients(&self, identifier: &str) -> Result<Vec<String>, String> {
        let hostname = identifier.to_string();
        let store = Arc::clone(&self.store);
        let guard = store.lock_owned().await;
        tokio::task::spawn_blocking(move || guard.challenge_recipients(&hostname))
            .await
            .map_err(|e| format!("challenge recipient lookup failed: {e}"))?
            .map_err(|e| e.to_string())
    }
}

#[async_trait::async_trait]
impl Http01ChallengeSolver for FleetHttp01Solver {
    async fn present(
        &self,
        identifier: &str,
        token: String,
        key_authorization: String,
    ) -> Result<(), AcmeError> {
        // Local first, and unconditionally: this node serves traffic
        // too, and the authority may well validate against it.
        self.local
            .set(token.clone(), key_authorization.clone())
            .await
            .map_err(AcmeError::Solver)?;

        let ClusterRuntime::ControlPlane(runtime) = &self.cluster else {
            return Ok(());
        };

        let recipients = self.recipients(identifier).await.map_err(|reason| {
            // A resolution failure is NOT "nobody needs it": it is not
            // knowing who does. Refusing here is what keeps the
            // all-or-nothing honest.
            AcmeError::Solver(format!(
                "could not resolve which nodes serve {identifier}: {reason}"
            ))
        })?;

        if recipients.is_empty() {
            if !runtime.control.sessions.is_empty() {
                tracing::warn!(
                    identifier,
                    "no route binds this hostname to any node, so the challenge is served only \
                     by this node; if the authority resolves the name to a follower, validation \
                     will fail"
                );
            }
            return Ok(());
        }

        let report = runtime
            .control
            .publish_challenge(&recipients, identifier, &token, &key_authorization)
            .await;
        if !report.failed.is_empty() {
            // Retract what did land before giving up, so a retried
            // order does not race tokens left behind by this one. The
            // driver also calls `cleanup`, but only for tokens it
            // recorded, and it is about to be handed an error.
            runtime
                .control
                .retract_challenge(&report.delivered, &token)
                .await;
            self.local.remove(&token).await;
            let (node_id, reason) = &report.failed[0];
            return Err(AcmeError::Solver(format!(
                "{} of {} nodes did not take the challenge for {identifier}; first failure on \
                 node {node_id}: {reason}",
                report.failed.len(),
                recipients.len()
            )));
        }
        tracing::info!(
            identifier,
            nodes = report.delivered.len(),
            "HTTP-01 challenge published across the fleet"
        );
        self.delivered_to
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .insert(token, report.delivered);
        Ok(())
    }

    async fn cleanup(&self, token: &str) {
        self.local.remove(token).await;
        let delivered = self
            .delivered_to
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .remove(token);
        let (Some(delivered), ClusterRuntime::ControlPlane(runtime)) = (delivered, &self.cluster)
        else {
            return;
        };
        // Best effort, like the local retraction it mirrors. A node
        // that misses this keeps the token until its deadline rather
        // than forever, which is what the expiry added by this story
        // is for.
        runtime.control.retract_challenge(&delivered, token).await;
    }
}
