// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Supervisor / single-process API server spawn helper.
//!
//! Story 8.1 AC #1+#3 - moved out of `run_supervisor` (was ~60 LOC
//! inline + 19 captures) so the supervisor boot path reads as a flat
//! sequence of helper calls. The same shape applies in
//! `run_single_process` ; both call paths construct an `AppState`,
//! pick a management port, and dispatch the alert sender to ACME
//! auto-renewal + cert-expiry background tasks before handing the
//! state to `lorica_api::server::start_server`.

use std::sync::Arc;

use tokio::task::JoinHandle;
use tracing::error;

use lorica_api::middleware::auth::SessionStore;
use lorica_api::middleware::rate_limit::RateLimiter;
use lorica_api::server::AppState;
use lorica_notify::AlertSender;

/// Spawn the management API server on `management_port` plus the
/// supporting ACME auto-renewal and cert-expiry notifier tasks.
///
/// The renewal task checks every 12 h and renews ACME-issued certs
/// 30 days before expiry. The cert-expiry notifier fires alerts via
/// `alert_sender` when any cert (uploaded or ACME) approaches expiry.
/// Both background tasks share the API task's lifetime - the
/// `JoinHandle` returned here aborts them transitively.
///
/// Worker mode (called from `run_supervisor`) wires both the renewal
/// task and the API server here ; pre-v1.5.2 the renewal task lived
/// only in single-process mode and worker-mode installs went through
/// cert expiry without warnings or auto-renewal. Single-process mode
/// (called from `run_single_process`) calls the same helper to keep
/// the two boot paths from drifting again.
pub fn spawn_api_server(
    state: AppState,
    management_port: u16,
    alert_sender: AlertSender,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let session_store = SessionStore::new(Arc::clone(&state.store))
            .await
            .with_task_tracker(state.task_tracker.clone());
        let rate_limiter = RateLimiter::new();

        // Spawn ACME auto-renewal (check every 12h, renew at 30 days
        // before expiry) and cert-expiry notifier. Previously these
        // tasks lived only in the single-process branch, so worker-
        // mode installs went through cert expiry without warnings and
        // never auto-renewed (v1.5.2 fix). Both modes now share this
        // helper so the asymmetry cannot return.
        let _acme_renewal = lorica_api::acme::spawn_renewal_task(
            state.clone(),
            std::time::Duration::from_secs(12 * 3600),
            30,
            Some(alert_sender.clone()),
        );
        let _cert_expiry_check = lorica_api::acme::spawn_cert_expiry_check_task(
            state.clone(),
            std::time::Duration::from_secs(12 * 3600),
            alert_sender,
        );

        if let Err(e) = lorica_api::server::start_server(
            management_port,
            state,
            session_store,
            rate_limiter,
        )
        .await
        {
            error!(error = %e, "API server exited with error");
        }
    })
}
