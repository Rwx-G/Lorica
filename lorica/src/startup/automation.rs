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

//! Starting the automation API listener (Story 10.3 slice 4).
//!
//! The listener itself lives in `lorica_api::automation`. What lives
//! here is everything a node must be sure of BEFORE that socket opens:
//! the bind is valid and collides with nothing, this node is not a
//! follower, and an operator has named the sources allowed to reach
//! it. Each of those is a refusal, not a warning: the flag is opt-in,
//! so an operator who passed it and got a silent no-op would learn
//! about it from the automation that never connected.
//!
//! The allowlist is also published here, so a later settings change
//! reaches the running accept loop. Narrowing it during an incident
//! used to need a restart, and nothing said so.

use std::net::SocketAddr;
use std::os::fd::{AsRawFd, FromRawFd, RawFd};
use std::sync::{Arc, OnceLock};

use lorica_api::automation::listener::publish_automation_source_policy;
use lorica_api::automation::{
    start_automation_server, AutomationListenerConfig, AutomationListenerError,
};
use lorica_api::server::AppState;
use lorica_config::ConfigStore;
use tokio::sync::Mutex;
use tokio::task::JoinHandle;
use tracing::{error, info, warn};

use crate::cli::{validate_automation_listen, ReservedPorts};
use crate::startup::cluster_plane::close_inherited_fd;

/// Inputs for [`prepare_automation_listener`], lifted from the CLI and
/// the process.
pub(crate) struct AutomationOptions {
    /// `--automation-listen`; the listener is off when `None`.
    pub automation_listen: Option<String>,
    /// `--automation-listen-any`.
    pub listen_any: bool,
    /// Ports the automation listener must never share. Its own port
    /// is cleared by the validator, so this may describe the whole
    /// process.
    pub reserved: ReservedPorts,
    /// Automation listening sockets inherited from an outgoing
    /// supervisor on `--hot-upgrade`, as `(bind, fd)`. Single-process
    /// mode never hot-upgrades and passes an empty slice.
    pub inherited: Vec<(String, RawFd)>,
    /// Where the long-lived dup of the listening socket is published
    /// for the NEXT hot upgrade. Single-process mode passes a slot it
    /// never reads.
    pub handoff: Arc<AutomationHandoff>,
}

/// The automation listener's hot-upgrade handoff slot: the bind and a
/// long-lived dup of the listening socket, in
/// [`crate::startup::hot_upgrade::HandoffArgs::automation_fds`] shape.
///
/// A slot rather than a return value because of where the two sides
/// run: the listener is started inside the API task, and the upgrade
/// that has to hand the descriptor over runs in the supervisor loop
/// outside it. The slot owns the dup for the process lifetime, which
/// is the point - dropping it would close the descriptor the next
/// binary is meant to accept on.
#[derive(Default)]
pub(crate) struct AutomationHandoff {
    published: OnceLock<(String, std::net::TcpListener)>,
}

impl AutomationHandoff {
    /// The automation entries for the hot-upgrade FD table. Empty
    /// until the listener opens, and empty for good when
    /// `--automation-listen` is absent.
    pub fn fds(&self) -> Vec<(String, RawFd)> {
        self.published
            .get()
            .map(|(bind, listener)| vec![(bind.clone(), listener.as_raw_fd())])
            .unwrap_or_default()
    }

    /// Record the dup. Called once, when the listener opens.
    pub fn publish(&self, bind: SocketAddr, listener: std::net::TcpListener) {
        let _ = self.published.set((bind.to_string(), listener));
    }
}

/// Start the automation listener, or refuse with the reason.
///
/// `Ok(None)` when `--automation-listen` is absent. The returned
/// handle is the accept loop; dropping it detaches the task.
///
/// # Errors
///
/// Returns the operator-facing refusal when the bind is invalid or
/// the socket cannot be opened, when this node holds a follower
/// identity, or when `automation_allowed_cidrs` is empty. The caller logs it and exits
/// non-zero, as it does for the cluster plane: running without the
/// listener the operator asked for is the wrong failure mode.
pub(crate) async fn prepare_automation_listener(
    opts: AutomationOptions,
    store: &Arc<Mutex<ConfigStore>>,
    state: AppState,
) -> Result<Option<JoinHandle<()>>, String> {
    let Some(value) = opts.automation_listen.as_deref() else {
        for (bind, fd) in opts.inherited {
            warn!(
                inherited = %bind,
                "hot upgrade: inherited an automation listener but --automation-listen is not set; closing it"
            );
            close_inherited_fd(fd);
        }
        return Ok(None);
    };
    let addr: std::net::SocketAddr =
        validate_automation_listen(value, opts.reserved, opts.listen_any)?;

    let (is_follower, allowed_cidrs) = {
        let store = store.lock().await;
        // `is_follower` rather than a local read of the identity: one
        // definition of the question, and one fail-closed answer when
        // the store cannot be read. Here that answer refuses to open
        // the socket, which is the same "do not write" disposition the
        // sweeps get.
        let follower = store.is_follower();
        let settings = store
            .get_global_settings()
            .map_err(|e| format!("automation listener: failed to read the global settings: {e}"))?;
        (follower, settings.automation_allowed_cidrs)
    };
    if let Some(refusal) = refuse_to_listen(is_follower, &allowed_cidrs) {
        return Err(refusal);
    }

    let config: AutomationListenerConfig = AutomationListenerConfig::new(addr, &allowed_cidrs)
        .map_err(|e| format!("automation listener: {e}"))?;
    // Published BEFORE the accept loop is spawned, so a config reload
    // that lands during startup narrows the allowlist the loop is
    // about to read rather than being dropped on the floor. The
    // reload path reaches the listener through this slot; see
    // `lorica_api::automation::listener::reload_automation_source_policy`.
    publish_automation_source_policy(&config.allowed_cidrs);

    // Adopt the socket the outgoing supervisor handed over, so this
    // process accepts on the SAME kernel socket instead of racing the
    // old one for the port. A fresh bind during the overlap is an
    // EADDRINUSE and a listener that never opens.
    let std_listener: std::net::TcpListener = match adopt_inherited(&opts.inherited, addr) {
        Some(inherited) => inherited,
        None => std::net::TcpListener::bind(addr)
            .map_err(|e| format!("automation listener: failed to bind {addr}: {e}"))?,
    };
    std_listener
        .set_nonblocking(true)
        .map_err(|e| format!("automation listener: listener non-blocking: {e}"))?;
    // The dup outlives this function on purpose: the next upgrade
    // hands over this descriptor, and the accept loop below owns the
    // original.
    let handoff_listener: std::net::TcpListener = std_listener
        .try_clone()
        .map_err(|e| format!("automation listener: failed to dup the listener for handoff: {e}"))?;
    opts.handoff.publish(addr, handoff_listener);

    // WARN, not INFO, for the reason the cluster plane uses: a listener
    // that accepts configuration writes from off-box is a fact an
    // operator must be able to spot in the journal.
    warn!(
        addr = %addr,
        allowed_cidrs = config.allowed_cidrs.entries(),
        "automation API enabled: listener bound (bearer tokens only, source-filtered)"
    );

    Ok(Some(tokio::spawn(async move {
        match start_automation_server(config, state, Some(std_listener)).await {
            Ok(()) => info!("automation listener stopped"),
            Err(e) => {
                let e: AutomationListenerError = e;
                error!(error = %e, "automation listener exited with error");
            }
        }
    })))
}

/// The two refusals that depend on node state rather than on the CLI,
/// as the operator-facing message, or `None` when the listener may
/// open. Pure, so both refusals have exactly one wording and the tests
/// assert the wording an operator actually reads.
fn refuse_to_listen(is_follower: bool, allowed_cidrs: &[String]) -> Option<String> {
    if is_follower {
        return Some(
            "automation listener: this node holds a follower identity (it joined a fleet) and \
             --automation-listen was passed; a follower's configuration is replaced by the \
             control plane on the next replication round, so an automation write here would be \
             silently lost. Point the automation at the control plane, or run \
             `lorica cluster leave` first"
                .to_string(),
        );
    }
    if allowed_cidrs.iter().all(|entry| entry.trim().is_empty()) {
        return Some(
            "automation listener: `automation_allowed_cidrs` is empty and --automation-listen \
             was passed; the listener will not open without one, because a network-reachable \
             configuration API with no source allowlist is not a default anyone should get by \
             omission. Set it in the global settings first"
                .to_string(),
        );
    }
    None
}

/// Pick the automation socket to serve on out of what an outgoing
/// supervisor handed over, and close the rest.
///
/// Only the socket bound where THIS process is configured to listen is
/// adopted, the same guard the cluster plane applies: a divergent bind
/// means the two binaries disagree about the configuration, and
/// serving the old socket while logging the new address would be
/// undebuggable. Everything not adopted is closed here, because a
/// descriptor received via SCM_RIGHTS and then forgotten leaks for the
/// process lifetime.
fn adopt_inherited(
    inherited: &[(String, RawFd)],
    configured: SocketAddr,
) -> Option<std::net::TcpListener> {
    let configured_bind = configured.to_string();
    let mut adopted: Option<std::net::TcpListener> = None;
    for (bind, fd) in inherited {
        if *bind == configured_bind && adopted.is_none() {
            info!(
                inherited = %bind,
                "hot upgrade: adopting the inherited automation listener"
            );
            // SAFETY: `fd` was received via SCM_RIGHTS in
            // `pull_inherited_listeners` and is owned exclusively by
            // this process; it refers to the same kernel listening
            // socket the outgoing supervisor accepts automation
            // connections on, and this is the only place it is
            // wrapped (the loop adopts at most one entry, and every
            // other one is closed below).
            adopted = Some(unsafe { std::net::TcpListener::from_raw_fd(*fd) });
            continue;
        }
        info!(
            inherited = %bind,
            configured = %configured_bind,
            "hot upgrade: closing an inherited automation listener this process does not adopt"
        );
        close_inherited_fd(*fd);
    }
    adopted
}

#[cfg(test)]
mod tests {
    use super::*;
    use lorica_config::models::ClusterIdentity;

    const RESERVED: ReservedPorts = ReservedPorts {
        management: 9443,
        http: 8080,
        https: 8443,
        cluster: None,
        automation: None,
    };

    fn follower_identity() -> ClusterIdentity {
        let now = chrono::Utc::now();
        ClusterIdentity {
            node_id: "00000000-0000-4000-8000-000000000001".to_string(),
            node_name: "follower01".to_string(),
            cert_pem: String::new(),
            key_pem: String::new(),
            ca_pem: String::new(),
            control_plane: "cp.internal:9444".to_string(),
            server_name: "cp.internal".to_string(),
            enrolled_at: now,
            cert_not_after: now + chrono::Duration::days(90),
        }
    }

    #[test]
    fn a_follower_refuses_to_open_the_automation_listener() {
        // The refusal must name the control plane: an operator whose
        // automation writes vanish on the next replication round needs
        // to be told where the writes belong, not just that this node
        // said no.
        let refusal = refuse_to_listen(true, &["10.0.0.0/8".to_string()])
            .expect("a follower must refuse the listener");
        assert!(refusal.contains("follower identity"), "{refusal}");
        assert!(refusal.contains("control plane"), "{refusal}");
        assert!(refusal.contains("--automation-listen"), "{refusal}");

        // A complete allowlist on a non-follower opens the listener,
        // so the refusal above can only have come from the identity.
        assert!(refuse_to_listen(false, &["10.0.0.0/8".to_string()]).is_none());
    }

    #[test]
    fn an_empty_allowlist_refuses_to_open_the_automation_listener() {
        let refusal = refuse_to_listen(false, &[]).expect("an empty allowlist must refuse");
        assert!(refusal.contains("automation_allowed_cidrs"), "{refusal}");
        assert!(refusal.contains("will not open"), "{refusal}");

        // A list of blanks is not a list: the underlying config would
        // reject it seconds later, and refusing here keeps the reason
        // the operator reads the same in both cases.
        assert!(refuse_to_listen(false, &["  ".to_string()]).is_some());
    }

    #[test]
    fn a_fresh_store_has_no_allowlist_and_no_fleet_identity() {
        // The two inputs `prepare_automation_listener` reads, from a
        // store that was never configured: the default must be the
        // refusal, not an open socket.
        let store = ConfigStore::open_in_memory().expect("test store opens");
        let settings = store.get_global_settings().expect("settings read");
        assert!(settings.automation_allowed_cidrs.is_empty());
        let is_follower = store.is_follower();
        assert!(!is_follower);
        assert!(refuse_to_listen(is_follower, &settings.automation_allowed_cidrs).is_some());

        // And once both are set the way a control plane has them, the
        // same two reads let the listener open.
        let mut settings = settings;
        settings.automation_allowed_cidrs = vec!["10.0.0.0/8".to_string()];
        store
            .update_global_settings(&settings)
            .expect("settings write");
        let stored = store.get_global_settings().expect("settings re-read");
        assert_eq!(stored.automation_allowed_cidrs, vec!["10.0.0.0/8"]);
        assert!(refuse_to_listen(false, &stored.automation_allowed_cidrs).is_none());

        // The same store, now holding a follower identity, refuses.
        store
            .set_cluster_identity(&follower_identity())
            .expect("identity write");
        assert!(store.is_follower());
        assert!(refuse_to_listen(true, &stored.automation_allowed_cidrs).is_some());
    }

    #[test]
    fn the_inherited_socket_is_adopted_not_rebound() {
        use std::os::fd::IntoRawFd;

        let live = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("test listener");
        let configured = live.local_addr().expect("test bind address");
        let stray = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("second test listener");
        let stray_bind = stray.local_addr().expect("test bind address");

        let adopted = adopt_inherited(
            &[
                (
                    stray_bind.to_string(),
                    stray.try_clone().expect("test dup").into_raw_fd(),
                ),
                (
                    configured.to_string(),
                    live.try_clone().expect("test dup").into_raw_fd(),
                ),
            ],
            configured,
        )
        .expect("the socket bound where this process listens is adopted");
        // The SAME kernel socket, which is the whole point: a rebind
        // during the overlap with the outgoing supervisor is an
        // EADDRINUSE and a listener that never opens.
        assert_eq!(adopted.local_addr().expect("adopted bind"), configured);

        // A descriptor bound somewhere else is closed, never served:
        // the two binaries disagreeing about the bind is not a reason
        // to accept on an address nothing logs.
        assert!(adopt_inherited(
            &[(
                stray_bind.to_string(),
                stray.try_clone().expect("test dup").into_raw_fd()
            )],
            configured,
        )
        .is_none());
    }

    #[test]
    fn the_bind_is_validated_under_the_automation_flag_names() {
        // `prepare_automation_listener` delegates to the shared
        // validator; this pins the flag names an operator sees.
        let err = validate_automation_listen("9600", RESERVED, false)
            .expect_err("a bare port is refused");
        assert!(err.starts_with("--automation-listen "), "{err}");
        assert!(
            validate_automation_listen("192.0.2.10:9600", RESERVED, false).is_ok(),
            "an explicit host:port on a free port is accepted"
        );
    }
}
