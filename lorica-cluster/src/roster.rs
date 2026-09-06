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

//! The control plane's in-memory view of its fleet (Story 9.3 AC #7/#8):
//! the [`Roster`] that maps certificate fingerprints to identities,
//! the [`SessionRegistry`] of live sessions with their kill switches,
//! and the [`ControlPlane`] handle that bundles them with the acceptor
//! and the CA so the management API can act on the fleet.
//!
//! The store stays the source of truth; the binary reloads the roster
//! after every registry mutation (enroll, activate, revoke, renew), so
//! a connection never touches SQLite and the transport crate never
//! depends on it.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use arc_swap::ArcSwap;
use tokio::sync::watch;

use crate::ca::{CaError, ClusterCa, IssuedLeaf, RevokedEntry};
use crate::tls::{operational_server_config_with_crl, ClusterTlsError, SwappableAcceptor};

/// Lifecycle state of a roster entry, mirroring the registry's
/// `status` column without depending on the config crate.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeState {
    /// Enrolled, not yet activated: sessions are admitted (liveness,
    /// visibility) but no configuration or certificate flows.
    Pending,
    /// Full fleet member.
    Active,
    /// Refused: the certificate is on the CRL; a session that somehow
    /// reaches identity resolution is dropped and audited.
    Revoked,
}

/// One enrolled node as the transport sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeIdentity {
    /// Server-assigned node id (the only identity the plane uses).
    pub node_id: String,
    /// Display name (never an authorization input).
    pub name: String,
    /// Lifecycle state.
    pub state: NodeState,
    /// Whether the presented certificate is the superseded one a
    /// renewal left behind: the session layer retires it once the
    /// node connects with the new one.
    pub via_previous_certificate: bool,
}

/// Fingerprint -> identity map, swapped wholesale on every registry
/// change; reads are lock-free.
#[derive(Default)]
pub struct Roster {
    by_fingerprint: ArcSwap<HashMap<String, NodeIdentity>>,
}

impl Roster {
    /// An empty roster.
    pub fn new() -> Self {
        Self::default()
    }

    /// Replace the whole map (the binary builds it from the store).
    pub fn replace(&self, entries: HashMap<String, NodeIdentity>) {
        self.by_fingerprint.store(Arc::new(entries));
    }

    /// The identity behind a certificate fingerprint, if enrolled.
    pub fn lookup(&self, fingerprint: &str) -> Option<NodeIdentity> {
        self.by_fingerprint.load().get(fingerprint).cloned()
    }

    /// Enrolled nodes (any state), for the fleet-size hint.
    pub fn len(&self) -> usize {
        self.by_fingerprint
            .load()
            .values()
            .filter(|n| !n.via_previous_certificate)
            .count()
    }

    /// Whether no node is enrolled.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Live facts about one established session, updated by the session
/// layer and read by the API and the persistence flush.
#[derive(Debug)]
pub struct LiveSession {
    /// Monotonic per control plane; a newer session for the same node
    /// supersedes the older one.
    pub generation: u64,
    /// The peer's transport address.
    pub peer_addr: SocketAddr,
    /// Unix seconds of the last heartbeat or session event.
    pub last_seen_unix: AtomicU64,
    /// The node's reported build version.
    pub build_version: String,
    /// The node's reported schema version.
    pub schema_version: u32,
    /// Flipped to `true` to end the session synchronously (revocation,
    /// supersession).
    kill: watch::Sender<bool>,
}

impl LiveSession {
    /// Record activity now.
    pub fn touch(&self) {
        self.last_seen_unix.store(unix_now(), Ordering::Relaxed);
    }
}

/// A snapshot of one live session for the API.
#[derive(Debug, Clone)]
pub struct LiveSessionSnapshot {
    /// The node id.
    pub node_id: String,
    /// Session generation.
    pub generation: u64,
    /// The peer's transport address.
    pub peer_addr: SocketAddr,
    /// Unix seconds of the last activity.
    pub last_seen_unix: u64,
    /// Reported build version.
    pub build_version: String,
    /// Reported schema version.
    pub schema_version: u32,
}

/// Node id -> live session, with per-session kill switches so a
/// revocation ends the session NOW rather than at the next heartbeat
/// (AC #7).
#[derive(Default)]
pub struct SessionRegistry {
    sessions: Mutex<HashMap<String, Arc<LiveSession>>>,
    next_generation: AtomicU64,
}

/// What a session task holds while registered: its kill receiver and
/// the entry itself. Dropping the guard deregisters the session, but
/// only if a newer session has not already replaced it.
pub struct SessionGuard {
    registry: Arc<SessionRegistry>,
    node_id: String,
    entry: Arc<LiveSession>,
    killed: watch::Receiver<bool>,
}

impl SessionGuard {
    /// The live entry (for `touch`).
    pub fn entry(&self) -> &Arc<LiveSession> {
        &self.entry
    }

    /// Resolves when the session is told to end (revoked or superseded).
    pub async fn killed(&mut self) {
        while !*self.killed.borrow() {
            if self.killed.changed().await.is_err() {
                return;
            }
        }
    }
}

impl Drop for SessionGuard {
    fn drop(&mut self) {
        let mut sessions = self.registry.sessions.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(current) = sessions.get(&self.node_id) {
            if Arc::ptr_eq(current, &self.entry) {
                sessions.remove(&self.node_id);
            }
        }
    }
}

impl SessionRegistry {
    /// An empty registry.
    pub fn new() -> Arc<Self> {
        Arc::new(Self::default())
    }

    /// Register a session for `node_id`, superseding (and killing) any
    /// older one for the same node: a node has exactly one operational
    /// session, and the newest connection wins (a reconnect after a
    /// network blip must not lose to its own zombie).
    pub fn register(
        self: &Arc<Self>,
        node_id: &str,
        peer_addr: SocketAddr,
        build_version: &str,
        schema_version: u32,
    ) -> SessionGuard {
        let (kill_tx, kill_rx) = watch::channel(false);
        let entry = Arc::new(LiveSession {
            generation: self.next_generation.fetch_add(1, Ordering::Relaxed) + 1,
            peer_addr,
            last_seen_unix: AtomicU64::new(unix_now()),
            build_version: build_version.to_string(),
            schema_version,
            kill: kill_tx,
        });
        let previous = self
            .sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(node_id.to_string(), Arc::clone(&entry));
        if let Some(old) = previous {
            let _ = old.kill.send(true);
        }
        SessionGuard {
            registry: Arc::clone(self),
            node_id: node_id.to_string(),
            entry,
            killed: kill_rx,
        }
    }

    /// End the node's session synchronously (AC #7). `true` iff a
    /// session was live.
    pub fn kill(&self, node_id: &str) -> bool {
        let removed = self
            .sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(node_id);
        match removed {
            Some(entry) => {
                let _ = entry.kill.send(true);
                true
            }
            None => false,
        }
    }

    /// Whether the node has a live session.
    pub fn is_connected(&self, node_id: &str) -> bool {
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .contains_key(node_id)
    }

    /// Snapshot of every live session.
    pub fn snapshot(&self) -> Vec<LiveSessionSnapshot> {
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .iter()
            .map(|(node_id, s)| LiveSessionSnapshot {
                node_id: node_id.clone(),
                generation: s.generation,
                peer_addr: s.peer_addr,
                last_seen_unix: s.last_seen_unix.load(Ordering::Relaxed),
                build_version: s.build_version.clone(),
                schema_version: s.schema_version,
            })
            .collect()
    }

    /// Live sessions.
    pub fn len(&self) -> usize {
        self.sessions
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .len()
    }

    /// Whether no session is live.
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// Everything the management API needs to act on the fleet, owned by
/// the control-plane runtime and shared with `AppState`.
pub struct ControlPlane {
    /// Fingerprint -> identity.
    pub roster: Arc<Roster>,
    /// Live sessions and their kill switches.
    pub sessions: Arc<SessionRegistry>,
    /// The operational acceptor, rebuilt with a fresh CRL on every
    /// revocation.
    pub acceptor: Arc<SwappableAcceptor>,
    /// The fleet CA. Private: signing reaches the API only through
    /// [`ControlPlane::issue_node_leaf`] and the CRL rebuild, never
    /// as a bare signer any handler could misuse.
    ca: ClusterCa,
    /// The serials the current acceptor's CRL covers, so a refresh
    /// that changes nothing revocation-related skips the mint and
    /// the rustls rebuild.
    crl_serials: Mutex<Vec<String>>,
    /// Serializes "read the store, swap roster and acceptor" so two
    /// concurrent refreshes cannot land out of order and undo a
    /// revocation. Held by the caller across the whole refresh.
    pub refresh_lock: tokio::sync::Mutex<()>,
    /// The control plane's own leaf, PEM (its SPKI is what tokens pin).
    pub leaf_cert_pem: String,
    /// The control plane's own leaf key, PEM (for the acceptor rebuild).
    leaf_key_pem: String,
    /// Fleet-size hint handed to followers.
    pub fleet_size: Arc<AtomicU32>,
    /// Live join-token count driving the enrollment listener.
    pub token_liveness: watch::Sender<u32>,
    /// `--cluster-auto-activate`: enrollments land `Active` instead of
    /// `Pending`.
    pub auto_activate: bool,
    /// The name followers dial (the leaf SAN).
    pub advertise_host: String,
    /// This control plane's build version (reported in `cluster
    /// status`).
    pub build_version: String,
}

impl ControlPlane {
    /// Bundle the runtime handles. `token_liveness` starts at 0; the
    /// binary's liveness publisher raises it.
    #[allow(clippy::too_many_arguments)] // one constructor for one bundle; the fields ARE the API
    pub fn new(
        ca: ClusterCa,
        leaf_cert_pem: &str,
        leaf_key_pem: &str,
        acceptor: Arc<SwappableAcceptor>,
        fleet_size: Arc<AtomicU32>,
        token_liveness: watch::Sender<u32>,
        auto_activate: bool,
        advertise_host: &str,
        build_version: &str,
    ) -> Self {
        Self {
            roster: Arc::new(Roster::new()),
            sessions: SessionRegistry::new(),
            acceptor,
            ca,
            crl_serials: Mutex::new(Vec::new()),
            refresh_lock: tokio::sync::Mutex::new(()),
            leaf_cert_pem: leaf_cert_pem.to_string(),
            leaf_key_pem: leaf_key_pem.to_string(),
            fleet_size,
            token_liveness,
            auto_activate,
            advertise_host: advertise_host.to_string(),
            build_version: build_version.to_string(),
        }
    }

    /// Replace the roster and refresh the fleet-size hint.
    pub fn replace_roster(&self, entries: HashMap<String, NodeIdentity>) {
        self.roster.replace(entries);
        let size = u32::try_from(self.roster.len()).unwrap_or(u32::MAX);
        self.fleet_size.store(size, Ordering::Relaxed);
    }

    /// The CA certificate PEM (what enrolled nodes verify the control
    /// plane with).
    pub fn ca_pem(&self) -> &str {
        self.ca.cert_pem()
    }

    /// Issue a node leaf on a bare public key (AC #3), the only
    /// signing path the API and the redemption hooks get.
    pub fn issue_node_leaf(&self, node_id: &str, spki_der: &[u8]) -> Result<IssuedLeaf, CaError> {
        self.ca.issue_node_leaf_for_public_key(node_id, spki_der)
    }

    /// Rebuild the operational acceptor over `revoked` (AC #7): mints
    /// a CRL when the list is non-empty, swaps the config in, so every
    /// accept from now on refuses those serials. Established sessions
    /// are handled separately by [`SessionRegistry::kill`]. A call
    /// whose serial set equals the one already served is a no-op
    /// (`Ok(false)`); `Ok(true)` means the acceptor was swapped.
    pub fn rebuild_acceptor(&self, revoked: &[RevokedEntry]) -> Result<bool, ClusterTlsError> {
        let mut serials: Vec<String> = revoked.iter().map(|r| r.serial_hex.clone()).collect();
        serials.sort();
        {
            let current = self.crl_serials.lock().unwrap_or_else(|p| p.into_inner());
            if *current == serials {
                return Ok(false);
            }
        }
        let crl = if revoked.is_empty() {
            None
        } else {
            Some(
                self.ca
                    .mint_crl(revoked)
                    .map_err(|e| ClusterTlsError::Rustls(format!("CRL: {e}")))?,
            )
        };
        let config = operational_server_config_with_crl(
            self.ca.cert_pem(),
            &self.leaf_cert_pem,
            &self.leaf_key_pem,
            crl,
        )?;
        self.acceptor.swap(Arc::new(config));
        *self.crl_serials.lock().unwrap_or_else(|p| p.into_inner()) = serials;
        Ok(true)
    }

    /// Publish the live-token count to the enrollment listener.
    pub fn publish_token_liveness(&self, live: u32) {
        let _ = self.token_liveness.send(live);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn identity(id: &str, state: NodeState) -> NodeIdentity {
        NodeIdentity {
            node_id: id.to_string(),
            name: id.to_string(),
            state,
            via_previous_certificate: false,
        }
    }

    #[test]
    fn roster_lookup_and_size_ignore_superseded_entries() {
        let roster = Roster::new();
        assert!(roster.is_empty());
        let mut map = HashMap::new();
        map.insert("fp-a".to_string(), identity("a", NodeState::Active));
        map.insert("fp-b".to_string(), identity("b", NodeState::Pending));
        map.insert(
            "fp-b-old".to_string(),
            NodeIdentity {
                via_previous_certificate: true,
                ..identity("b", NodeState::Pending)
            },
        );
        roster.replace(map);
        assert_eq!(roster.len(), 2);
        assert_eq!(roster.lookup("fp-a").map(|n| n.node_id), Some("a".to_string()));
        assert!(roster.lookup("fp-b-old").is_some_and(|n| n.via_previous_certificate));
        assert!(roster.lookup("fp-zzz").is_none());
    }

    #[tokio::test]
    async fn a_newer_session_supersedes_and_kills_the_older_one() {
        let registry = SessionRegistry::new();
        let peer: SocketAddr = "192.0.2.10:4000".parse().expect("addr");
        let mut first = registry.register("node-a", peer, "1.7.0", 50);
        assert!(registry.is_connected("node-a"));
        let second = registry.register("node-a", peer, "1.7.0", 50);
        assert!(second.entry().generation > first.entry().generation);
        tokio::time::timeout(std::time::Duration::from_secs(1), first.killed())
            .await
            .expect("older session is told to end");
        // Dropping the superseded guard must not deregister the newer
        // session.
        drop(first);
        assert!(registry.is_connected("node-a"));
        assert_eq!(registry.len(), 1);
        drop(second);
        assert!(!registry.is_connected("node-a"));
    }

    #[tokio::test]
    async fn kill_ends_a_live_session_synchronously() {
        let registry = SessionRegistry::new();
        let peer: SocketAddr = "192.0.2.10:4000".parse().expect("addr");
        let mut guard = registry.register("node-a", peer, "1.7.0", 50);
        assert!(registry.kill("node-a"));
        tokio::time::timeout(std::time::Duration::from_secs(1), guard.killed())
            .await
            .expect("killed resolves");
        assert!(!registry.kill("node-a"), "nothing left to kill");
        assert!(registry.snapshot().is_empty());
    }
}
