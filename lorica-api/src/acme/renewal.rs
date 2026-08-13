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

//! Background renewal task and manual renewal endpoint.

use std::collections::{HashMap, HashSet};

use axum::extract::{Extension, Path};
use axum::Json;
use chrono::{DateTime, Utc};
use tracing::{error, info, warn};

use crate::db::db_blocking;
use crate::error::ApiError;
use crate::middleware::auth::Session;
use crate::server::AppState;

/// Pure predicate : does this certificate qualify for automated ACME
/// renewal at `now`, given a "renew when days_remaining ≤ threshold"
/// policy ? Returns `true` when ALL of the following are true :
///
/// - `cert.is_acme == true` (uploaded / self-signed certs are never
///   renewed automatically, regardless of their expiry)
/// - `cert.acme_auto_renew == true` (operator has opted in to auto-
///   renewal for this cert)
/// - `(cert.not_after - now).num_days() <= threshold_days` (inside
///   the renewal window)
/// - `cert.acme_method != Some("dns01-manual")` (manual DNS-01
///   flows require a human — the auto-renewal loop cannot fire
///   them, see the `spawn_renewal_task` body for the handling)
///
/// Extracted so the filtering logic is unit-testable without
/// spawning the background task or hitting the network.
pub(super) fn should_auto_renew(
    cert: &lorica_config::models::Certificate,
    now: chrono::DateTime<chrono::Utc>,
    threshold_days: i64,
) -> bool {
    if !cert.is_acme || !cert.acme_auto_renew {
        return false;
    }
    if cert.acme_method.as_deref() == Some("dns01-manual") {
        return false;
    }
    let days_remaining = (cert.not_after - now).num_days();
    days_remaining <= threshold_days
}

/// Pure predicate : is `cert_id` referenced by at least one route ?
///
/// The auto-renewal loop renews only route-bound certificates. An
/// unbound ACME cert renewed in place would never be served and, in
/// the old insert-then-reassign design, spawned an unbound duplicate
/// on every cycle (the 2026-06-16 `mail.kaliaops.com` incident). The
/// `bound_ids` set is built from `routes.certificate_id` exactly like
/// the resolver's active-cert derivation in `reload_cert_resolver`.
pub(super) fn is_bound(cert_id: &str, bound_ids: &HashSet<String>) -> bool {
    bound_ids.contains(cert_id)
}

/// Pure classifier : when `msg` is a Let's Encrypt rate-limit error,
/// return the cooldown instant before which the loop must not re-
/// attempt this certificate ; otherwise return `None`.
///
/// A rate-limit error is detected by the ACME problem-type URN
/// (`rateLimited`) or the human-readable "too many certificates"
/// phrasing. When present, the `retry after <stamp>` timestamp
/// (`%Y-%m-%d %H:%M:%S` UTC, e.g. `2026-06-11 06:19:40 UTC`) drives
/// the cooldown ; if no stamp parses, a safe 24h default from `now`
/// is used so the loop still backs off.
pub(super) fn cooldown_from_error(msg: &str, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
    let is_rate_limited = msg.contains("rateLimited") || msg.contains("too many certificates");
    if !is_rate_limited {
        return None;
    }

    // A Let's Encrypt rate-limit window never legitimately exceeds the
    // 168h (7 day) accounting period. Clamp the parsed deadline so a
    // malformed or hostile `retry after` (a far-future stamp from a
    // compromised or buggy ACME endpoint) cannot suspend auto-renewal
    // long enough to let the live certificate silently expire.
    let max_cooldown = now + chrono::Duration::days(7);
    if let Some(after) = msg.split("retry after ").nth(1) {
        // The stamp is followed by " UTC"; take everything up to it.
        let stamp = after.split(" UTC").next().unwrap_or(after).trim();
        if let Ok(naive) = chrono::NaiveDateTime::parse_from_str(stamp, "%Y-%m-%d %H:%M:%S") {
            let parsed = DateTime::from_naive_utc_and_offset(naive, Utc);
            return Some(parsed.min(max_cooldown));
        }
    }

    Some(now + chrono::Duration::hours(24))
}

/// Pure predicate : is `cert_id` within an active rate-limit cooldown
/// at `now` ? Extracted so the auto-renewal loop's skip decision (AC3)
/// is unit-testable without the network-bound renewal path.
pub(super) fn in_cooldown(
    cooldown: &HashMap<String, DateTime<Utc>>,
    cert_id: &str,
    now: DateTime<Utc>,
) -> bool {
    cooldown.get(cert_id).is_some_and(|until| *until > now)
}

/// Pure selector : among `certs`, return the ids of ACME certificates
/// that are BOTH unreferenced by any route AND superseded by a sibling
/// (same identifier set, strictly later `not_after`).
///
/// The identifier set is the UNION of the primary `domain` and the
/// `san_domains`, sorted and de-duplicated. Keying on the union (not
/// the `(domain, sans)` pair) means an uploaded twin that stores its
/// SANs without repeating the primary still matches an ACME cert that
/// lists the primary inside its SAN set: both cover the same names, so
/// both share one identity, and ordering differences never defeat the
/// match. A unique unbound cert with no newer sibling is kept (an
/// operator may still bind it) ; the newest cert of a duplicate group
/// is kept (nothing supersedes it), and ties on `not_after` keep both.
///
/// Used by the startup purge (AC4) to clear the orphan rows the old
/// insert-then-reassign renewal accumulated before this fix.
pub fn superseded_orphans(
    certs: &[lorica_config::models::Certificate],
    bound_ids: &HashSet<String>,
) -> Vec<String> {
    fn identity_key(cert: &lorica_config::models::Certificate) -> Vec<String> {
        let mut names: Vec<String> = cert.san_domains.clone();
        names.push(cert.domain.clone());
        names.sort();
        names.dedup();
        names
    }

    // One pass to record the latest `not_after` per identity, so the
    // supersede test below is O(n) rather than O(n^2).
    let mut latest: HashMap<Vec<String>, DateTime<Utc>> = HashMap::new();
    for cert in certs {
        latest
            .entry(identity_key(cert))
            .and_modify(|current| {
                if cert.not_after > *current {
                    *current = cert.not_after;
                }
            })
            .or_insert(cert.not_after);
    }

    certs
        .iter()
        .filter(|cert| cert.is_acme && !bound_ids.contains(&cert.id))
        .filter(|cert| {
            latest
                .get(&identity_key(cert))
                .is_some_and(|newest| *newest > cert.not_after)
        })
        .map(|cert| cert.id.clone())
        .collect()
}

use super::config::AcmeConfig;
use super::dns01::provision_with_acme_dns;
use super::dns_challengers::{build_dns_challenger, DnsChallengeConfig};
use super::http01::provision_with_acme;

/// Spawn a background task that checks ACME certificates for renewal.
///
/// Runs every `check_interval` and renews certificates where:
/// - `is_acme == true` and `acme_auto_renew == true`
/// - The cert is referenced by at least one route (unbound certs are
///   never auto-renewed, see [`is_bound`])
/// - Days until expiry <= `renewal_threshold_days`
///
/// On a Let's Encrypt rate-limit error the cert is put on a per-process
/// cooldown (see [`cooldown_from_error`]) so the loop stops hammering
/// the ACME endpoint until the quota window reopens.
pub fn spawn_renewal_task(
    state: AppState,
    check_interval: std::time::Duration,
    renewal_threshold_days: i64,
    alert_sender: Option<lorica_notify::AlertSender>,
) -> tokio::task::JoinHandle<()> {
    let tracker = state.task_tracker.clone();
    tracker.spawn(async move {
        // Per-process rate-limit cooldown, keyed by cert id. Declared
        // outside the loop so it persists across `check_interval`
        // ticks for the lifetime of the task. Not persisted across
        // restarts (out of scope for this patch).
        let mut rate_limit_cooldown: HashMap<String, DateTime<Utc>> = HashMap::new();

        loop {
            tokio::time::sleep(check_interval).await;

            let certs = match db_blocking(&state.store, |store| store.list_certificates()).await {
                Ok(c) => c,
                Err(e) => {
                    warn!(error = %e, "ACME renewal: failed to list certificates");
                    continue;
                }
            };

            // Build the set of cert ids referenced by at least one
            // route, using the same derivation as the resolver
            // reload, so we never auto-renew an unbound cert.
            let bound_ids: HashSet<String> =
                match db_blocking(&state.store, |store| store.list_routes()).await {
                    Ok(routes) => routes
                        .iter()
                        .filter_map(|r| r.certificate_id.clone())
                        .collect(),
                    Err(e) => {
                        warn!(error = %e, "ACME renewal: failed to list routes");
                        continue;
                    }
                };

            let now = chrono::Utc::now();
            // Drop expired cooldown entries so the map stays bounded by
            // the count of currently rate-limited certs (a cert that is
            // decommissioned mid-cooldown is swept once its window ends).
            rate_limit_cooldown.retain(|_, until| *until > now);

            for cert in &certs {
                // Skip certs not bound to any route. An unbound cert
                // is never served, so renewing it is pure quota waste
                // and, before in-place renewal, spawned orphans.
                if !is_bound(&cert.id, &bound_ids) {
                    continue;
                }

                // Pre-filter via the pure `should_auto_renew` helper so
                // the branching stays unit-testable. The helper already
                // rules out non-ACME, opt-out, dns01-manual, and out-of-
                // window certs ; we add a separate notification arm
                // below for the "inside window but not eligible for
                // auto" case (dns01-manual), which the helper collapses
                // to `false` but the operator still wants to be alerted
                // about.
                if !cert.is_acme || !cert.acme_auto_renew {
                    continue;
                }
                let days_remaining = (cert.not_after - now).num_days();
                if days_remaining > renewal_threshold_days {
                    continue;
                }

                // Honour an active rate-limit cooldown before doing any
                // work for this cert (expired entries were swept above,
                // so a present entry is still active).
                if in_cooldown(&rate_limit_cooldown, &cert.id, now) {
                    if let Some(until) = rate_limit_cooldown.get(&cert.id) {
                        info!(
                            domain = %cert.domain,
                            cert_id = %cert.id,
                            retry_after = %until,
                            "skipping ACME renewal: rate-limit cooldown active"
                        );
                    }
                    continue;
                }

                info!(
                    domain = %cert.domain,
                    days_remaining = days_remaining,
                    threshold = renewal_threshold_days,
                    "ACME certificate approaching expiry, attempting renewal"
                );

                // Dispatch cert_expiring notification (fires for both
                // auto-renewable and dns01-manual certs, since the
                // operator wants to know about the upcoming expiry in
                // both cases).
                if let Some(ref sender) = alert_sender {
                    sender.send(
                        lorica_notify::AlertEvent::new(
                            lorica_notify::events::AlertType::CertExpiring,
                            format!(
                                "Certificate for {} expires in {} days",
                                cert.domain, days_remaining
                            ),
                        )
                        .with_detail("domain", cert.domain.clone())
                        .with_detail("days_remaining", days_remaining.to_string())
                        .with_detail("cert_id", cert.id.clone()),
                    );
                }

                // Skip dns01-manual certs from the ACME renewal call
                // itself — the operator must confirm the new TXT.
                if !should_auto_renew(cert, now, renewal_threshold_days) {
                    info!(
                        domain = %cert.domain,
                        "skipping auto-renewal for manual DNS-01 certificate"
                    );
                    continue;
                }

                let config = AcmeConfig {
                    staging: cert.issuer.contains("STAGING"),
                    contact_email: None,
                };

                // Renew with all domains (primary + SANs), deduplicated
                let mut all_domains = vec![cert.domain.clone()];
                for d in &cert.san_domains {
                    if !all_domains.contains(d) {
                        all_domains.push(d.clone());
                    }
                }
                // In-place renewal : the leaf is written back onto the
                // same row (`Some(cert.id)`), so the id and every route
                // binding survive. No reassign, no delete, no orphan.
                match renew_with_method(&state, cert, &config, &all_domains, Some(&cert.id)).await {
                    Ok(_) => {
                        rate_limit_cooldown.remove(&cert.id);
                        state.rotate_bot_hmac_on_cert_event().await;
                        state.notify_config_changed();
                        info!(
                            domain = %cert.domain,
                            cert_id = %cert.id,
                            acme_method = ?cert.acme_method,
                            "ACME certificate renewed successfully"
                        );
                    }
                    Err(e) => {
                        let msg = e.to_string();
                        if let Some(until) = cooldown_from_error(&msg, now) {
                            rate_limit_cooldown.insert(cert.id.clone(), until);
                            info!(
                                domain = %cert.domain,
                                cert_id = %cert.id,
                                retry_after = %until,
                                "ACME renewal rate-limited; cooldown recorded"
                            );
                        }
                        error!(
                            domain = %cert.domain,
                            error = %e,
                            days_remaining = days_remaining,
                            acme_method = ?cert.acme_method,
                            "ACME renewal failed - existing cert still active"
                        );
                    }
                }
            }
        }
    })
}

/// POST /api/v1/certificates/:id/renew - manually trigger ACME renewal for a certificate
pub async fn renew_certificate(
    connect_info: crate::audit::ClientConnectInfo,
    headers: http::HeaderMap,
    Extension(state): Extension<AppState>,
    Extension(session): Extension<Session>,
    Path(id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let cert = db_blocking(&state.store, move |store| {
        store
            .get_certificate(&id)?
            .ok_or_else(|| ApiError::NotFound(format!("certificate {id}")))
    })
    .await?;

    if !cert.is_acme {
        return Err(ApiError::BadRequest(
            "only ACME certificates can be renewed (use upload for manual certs)".into(),
        ));
    }

    let config = AcmeConfig {
        staging: cert.issuer.contains("STAGING") || cert.issuer.contains("(staging)"),
        contact_email: None,
    };

    // Renew with all domains (primary + SANs), deduplicated
    let mut all_domains = vec![cert.domain.clone()];
    for d in &cert.san_domains {
        if !all_domains.contains(d) {
            all_domains.push(d.clone());
        }
    }

    // In-place renewal : same id, route bindings untouched (AC1).
    renew_with_method(&state, &cert, &config, &all_domains, Some(&cert.id))
        .await
        .map_err(|e| ApiError::Internal(format!("ACME renewal failed: {e}")))?;

    state.rotate_bot_hmac_on_cert_event().await;
    state.notify_config_changed();

    tracing::info!(
        domain = %cert.domain,
        cert_id = %cert.id,
        "certificate manually renewed"
    );

    let payload = serde_json::json!({
        "renewed": true,
        "old_cert_id": cert.id,
        "new_cert_id": cert.id,
        "domain": cert.domain,
    });
    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::audit::record(
        &state,
        &audit_ctx,
        "certificate.renew",
        ("certificate", &cert.id),
        None,
        Some(&payload),
    )
    .await;

    // In-place renewal keeps the id, so `old_cert_id == new_cert_id`.
    // Both fields are retained for response-shape compatibility with
    // existing API clients (the dashboard types this exact shape).
    Ok(crate::error::json_data(payload))
}

/// Renew a certificate using the appropriate method based on `acme_method`.
///
/// - `"http01"` or `None` -> HTTP-01 (original behavior)
/// - `"dns01-cloudflare"` / `"dns01-route53"` / `"dns01-ovh"` -> decrypt config, build challenger
/// - `"dns01-manual"` -> error (requires manual renewal)
///
/// `existing_cert_id` is threaded to the provisioning helpers so the
/// renewed leaf updates that row in place (same id) rather than
/// inserting a new certificate.
async fn renew_with_method(
    state: &AppState,
    cert: &lorica_config::models::Certificate,
    config: &AcmeConfig,
    domains: &[String],
    existing_cert_id: Option<&str>,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let method = cert.acme_method.as_deref().unwrap_or("http01");

    match method {
        "http01" => provision_with_acme(state, config, domains, existing_cert_id).await,
        "dns01-manual" => Err("manual DNS-01 certificates require manual renewal - \
             use the provision-dns-manual endpoint"
            .into()),
        m if m.starts_with("dns01-") => {
            // Extract provider name from "dns01-provider"
            let provider = &m[6..];

            // Try new approach first: global DNS provider reference
            let (dns_config, dns_provider_id) = if let Some(ref pid) = cert.acme_dns_provider_id {
                let pid_owned = pid.clone();
                let dp = db_blocking(&state.store, move |store| {
                    store.get_dns_provider(&pid_owned).map_err(|e| {
                        ApiError::Internal(format!(
                            "failed to fetch DNS provider '{pid_owned}': {e}"
                        ))
                    })
                })
                .await?;
                let dp = dp.ok_or_else(|| {
                    format!(
                        "certificate references DNS provider '{pid}' which no longer exists - \
                         cannot auto-renew"
                    )
                })?;
                let cfg: DnsChallengeConfig = serde_json::from_str(&dp.config)
                    .map_err(|e| format!("failed to parse DNS provider config: {e}"))?;
                (cfg, Some(pid.clone()))
            } else {
                return Err(format!(
                    "certificate has method '{m}' but no DNS provider configured - \
                     cannot auto-renew"
                )
                .into());
            };

            // Verify provider matches
            if dns_config.provider != provider {
                return Err(format!(
                    "DNS config provider '{}' does not match method '{m}'",
                    dns_config.provider
                )
                .into());
            }

            let challenger = build_dns_challenger(&dns_config)
                .await
                .map_err(|e| format!("failed to build DNS challenger for renewal: {e}"))?;

            provision_with_acme_dns(
                state,
                config,
                domains,
                challenger.as_ref(),
                m,
                dns_provider_id,
                existing_cert_id,
            )
            .await
        }
        other => Err(format!("unknown ACME method: {other}").into()),
    }
}
