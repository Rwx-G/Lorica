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

//! Certificate expiry check task (alerts only - does not renew).

use tracing::{info, warn};

use crate::server::AppState;

/// Check all certificates for upcoming expiration and dispatch alerts.
///
/// This is a pure logic function (no loop, no sleep) so it can be unit-tested.
/// It reads `cert_warning_days` and `cert_critical_days` from `GlobalSettings`
/// and sends `CertExpiring` alerts for every certificate within those thresholds.
pub async fn check_cert_expiry(state: &AppState, alert_sender: &lorica_notify::AlertSender) {
    let (certs, settings) = {
        let store = state.store.lock().await;
        let certs = match store.list_certificates() {
            Ok(c) => c,
            Err(e) => {
                warn!(error = %e, "cert expiry check: failed to list certificates");
                return;
            }
        };
        let settings = match store.get_global_settings() {
            Ok(s) => s,
            Err(e) => {
                warn!(error = %e, "cert expiry check: failed to load global settings");
                return;
            }
        };
        (certs, settings)
    };

    let warning_days = i64::from(settings.cert_warning_days);
    let critical_days = i64::from(settings.cert_critical_days);
    let now = chrono::Utc::now();

    for cert in &certs {
        let days_remaining = (cert.not_after - now).num_days();

        if days_remaining > warning_days {
            continue;
        }

        let summary = if days_remaining <= critical_days {
            format!(
                "CRITICAL: Certificate for {} expires in {} days",
                cert.domain, days_remaining
            )
        } else {
            format!(
                "Certificate for {} expires in {} days",
                cert.domain, days_remaining
            )
        };

        info!(
            domain = %cert.domain,
            days_remaining = days_remaining,
            is_acme = cert.is_acme,
            "cert expiry check: certificate approaching expiry"
        );

        alert_sender.send(
            lorica_notify::AlertEvent::new(lorica_notify::events::AlertType::CertExpiring, summary)
                .with_detail("domain", cert.domain.clone())
                .with_detail("days_remaining", days_remaining.to_string())
                .with_detail("cert_id", cert.id.clone())
                .with_detail("is_acme", cert.is_acme.to_string()),
        );
    }
}

/// Spawn a background task that periodically checks ALL certificates for expiration.
///
/// Unlike `spawn_renewal_task` which only handles ACME auto-renew certs, this task
/// alerts on every certificate (ACME or manual) that is within the warning/critical
/// thresholds defined in `GlobalSettings`.
pub fn spawn_cert_expiry_check_task(
    state: AppState,
    check_interval: std::time::Duration,
    alert_sender: lorica_notify::AlertSender,
) -> tokio::task::JoinHandle<()> {
    let tracker = state.task_tracker.clone();
    tracker.spawn(async move {
        check_cert_expiry(&state, &alert_sender).await;
        loop {
            tokio::time::sleep(check_interval).await;
            check_cert_expiry(&state, &alert_sender).await;
        }
    })
}
