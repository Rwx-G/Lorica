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
use parking_lot::Mutex;
use tracing::{error, info, warn};

use crate::db::db_blocking;
use crate::error::ApiError;
use crate::middleware::auth::Session;
use crate::server::AppState;

/// The least time, in hours, an automation token must leave between two
/// renewals of one certificate.
///
/// Let's Encrypt issues at most five certificates per exact identifier
/// set per seven days, a renewal not asked for through ARI counts
/// against it, and every issuance here also rotates the node's
/// bot-protection HMAC, invalidating every visitor's verdict cookie. A
/// token asking twice inside this window is either retrying an order
/// that succeeded, which spends that budget for nothing, or looping,
/// which spends all of it and blocks the scheduled renewal for a week.
/// Two days keeps a token under four orders a week and leaves the
/// background loop, which renews on the same budget, its share. The
/// interval is read off the certificate's own `not_before`, which every
/// issuance path writes as the order's instant, so no column is added.
/// An operator's session is not held to it: the dashboard's renew is
/// unchanged.
pub const MIN_TOKEN_RENEWAL_INTERVAL_HOURS: i64 = 48;

/// What the two renewal paths, the background loop and the manual
/// endpoint, know about each certificate between calls (Story 11.2).
///
/// Held on `AppState`, one per process, because a token's renewals are
/// budgeted per certificate against what every other caller is doing
/// to that same id: a renewal the loop has in flight is one a token
/// must not start a second of, and a cooldown the CA imposed on the
/// loop is one the token must honour too. Before this the cooldown map
/// was the loop's local variable and the manual path could not see it.
#[derive(Debug, Default)]
pub struct RenewalLedger {
    /// Certificate ids with an ACME order open right now.
    in_flight: Mutex<HashSet<String>>,
    /// Per-certificate instant before which the CA's rate limit makes
    /// another order pointless, keyed by certificate id.
    cooldown: Mutex<HashMap<String, DateTime<Utc>>>,
}

impl RenewalLedger {
    /// An empty ledger: nothing in flight, nothing cooling down.
    pub fn new() -> RenewalLedger {
        RenewalLedger::default()
    }

    /// Mark `id` as having an order open, or `None` when it already
    /// has one. The mark is released when the returned value drops,
    /// whether the order completed, failed or the task unwound.
    pub fn begin(&self, id: &str) -> Option<InFlightRenewal<'_>> {
        self.in_flight
            .lock()
            .insert(id.to_string())
            .then(|| InFlightRenewal {
                ledger: self,
                id: id.to_string(),
            })
    }

    /// Whether `id` has an order open right now.
    pub fn is_in_flight(&self, id: &str) -> bool {
        self.in_flight.lock().contains(id)
    }

    /// The instant `id`'s cooldown ends, when one is active at `now`.
    pub fn cooldown_until(&self, id: &str, now: DateTime<Utc>) -> Option<DateTime<Utc>> {
        let cooldown = self.cooldown.lock();
        in_cooldown(&cooldown, id, now)
            .then(|| cooldown.get(id).copied())
            .flatten()
    }

    /// Record that the CA refused an order for `id` until `until`.
    pub fn record_cooldown(&self, id: &str, until: DateTime<Utc>) {
        self.cooldown.lock().insert(id.to_string(), until);
    }

    /// Forget `id`'s cooldown, after an order for it succeeded.
    pub fn clear_cooldown(&self, id: &str) {
        self.cooldown.lock().remove(id);
    }

    /// Drop every cooldown that has ended at `now`, so the map stays
    /// bounded by the count of currently rate-limited certificates.
    pub fn sweep_cooldowns(&self, now: DateTime<Utc>) {
        self.cooldown.lock().retain(|_, until| *until > now);
    }
}

/// The in-flight mark of one certificate's renewal, released on drop.
#[derive(Debug)]
pub struct InFlightRenewal<'a> {
    ledger: &'a RenewalLedger,
    id: String,
}

impl Drop for InFlightRenewal<'_> {
    fn drop(&mut self) {
        self.ledger.in_flight.lock().remove(&self.id);
    }
}

/// How often the actor may renew one certificate by hand.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RenewalBudget {
    /// An operator's session: as often as it asks. The dashboard's
    /// renew path, unchanged.
    Unbounded,
    /// An automation token: one order per certificate at a time (409),
    /// none within [`MIN_TOKEN_RENEWAL_INTERVAL_HOURS`] of the last
    /// issuance (429), and none while the CA holds the certificate in a
    /// cooldown the ledger recorded (429).
    PerCertificate,
}

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
///   flows require a human - the auto-renewal loop cannot fire
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

use lorica_acme::{build_dns_challenger, AcmeConfig, DnsChallengeConfig};

use super::dns01::provision_with_acme_dns;
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
        // The per-certificate cooldown and the in-flight marks live on
        // `state.renewals`, shared with the manual renewal path, so a
        // token asking for a certificate this loop is ordering or the
        // CA has refused is told so. Not persisted across restarts.
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
            state.renewals.sweep_cooldowns(now);

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
                if let Some(until) = state.renewals.cooldown_until(&cert.id, now) {
                    info!(
                        domain = %cert.domain,
                        cert_id = %cert.id,
                        retry_after = %until,
                        "skipping ACME renewal: rate-limit cooldown active"
                    );
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
                // itself - the operator must confirm the new TXT.
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
                // One order per certificate at a time, across this loop
                // and the manual path: a manual renewal of this id that
                // is still open is left to finish.
                let Some(_in_flight) = state.renewals.begin(&cert.id) else {
                    info!(
                        domain = %cert.domain,
                        cert_id = %cert.id,
                        "skipping ACME renewal: an order for this certificate is in flight"
                    );
                    continue;
                };

                // In-place renewal : the leaf is written back onto the
                // same row (`Some(cert.id)`), so the id and every route
                // binding survive. No reassign, no delete, no orphan.
                match renew_with_method(&state, cert, &config, &all_domains, Some(&cert.id)).await {
                    Ok(_) => {
                        state.renewals.clear_cooldown(&cert.id);
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
                            state.renewals.record_cooldown(&cert.id, until);
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
    let audit_ctx = crate::audit::AuditContext::new(&session, connect_info.as_ref(), &headers);
    crate::db::run_detached(async move {
        renew_certificate_as(
            &state,
            &audit_ctx,
            id,
            crate::preview::WriteMode::Apply,
            crate::target::CertificateGuard::unbounded(),
            RenewalBudget::Unbounded,
        )
        .await
    })
    .await
}

/// The whole of [`renew_certificate`] as `actor`: the ACME-only
/// refusal, the in-place renewal, the reload signal and the
/// `certificate.renew` audit row.
///
/// Split from the handler so the automation plane (Story 11.2) can run
/// exactly this with a token as the actor rather than a session; see
/// `crate::routes::crud::create_route_as` for the rule and for what
/// `guard` is. The guard runs on the row as read, before the ACME-only
/// refusal, so a caller outside the grant learns nothing about the
/// row. No key material crosses this function's arguments: the renewal
/// is an ACME order the node makes for a row it already holds.
///
/// The method and the DNS provider are resolved before the preview
/// branch, by the same [`plan_renewal`] the apply then executes, so
/// what the apply would refuse the preview refuses with the same
/// words, as a 400 the row provoked rather than a 500 from inside the
/// order.
///
/// `budget` is what bounds a token: [`RenewalBudget::PerCertificate`]
/// refuses before the plan is resolved, so a token asking twice about a
/// certificate learns about its own pace before it learns about the
/// row, and its apply takes the in-flight mark the background loop and
/// every other renewal share. An operator's session passes
/// [`RenewalBudget::Unbounded`] and is refused by none of it; it takes
/// the mark when free, so a token asking meanwhile is told 409, and
/// proceeds unmarked otherwise, as it always did.
///
/// In [`crate::preview::WriteMode::Preview`] it answers the metadata of
/// the certificate that would be renewed and makes no order.
pub(crate) async fn renew_certificate_as(
    state: &AppState,
    actor: &crate::audit::AuditContext,
    id: String,
    mode: crate::preview::WriteMode,
    guard: crate::target::CertificateGuard,
    budget: RenewalBudget,
) -> Result<Json<serde_json::Value>, ApiError> {
    let (cert, provider) = db_blocking(&state.store, move |store| {
        let cert = store
            .get_certificate(&id)?
            .ok_or_else(|| ApiError::NotFound(format!("certificate {id}")))?;
        guard.check(&cert)?;
        let provider = match cert.acme_dns_provider_id.as_deref() {
            Some(provider_id) => store.get_dns_provider(provider_id)?,
            None => None,
        };
        Ok::<_, ApiError>((cert, provider))
    })
    .await?;

    if !cert.is_acme {
        return Err(ApiError::BadRequest(
            "only ACME certificates can be renewed (use upload for manual certs)".into(),
        ));
    }
    if budget == RenewalBudget::PerCertificate {
        ensure_token_renewal_budget(&state.renewals, &cert, Utc::now())?;
    }
    let plan = plan_renewal(&cert, provider.as_ref()).map_err(ApiError::BadRequest)?;
    if mode.previews() {
        return Ok(crate::preview::previewed(
            "renew",
            serde_json::to_value(crate::certificates::cert_to_response(&cert)).ok(),
            None,
        ));
    }
    let _in_flight = match (state.renewals.begin(&cert.id), budget) {
        (Some(mark), _) => Some(mark),
        (None, RenewalBudget::PerCertificate) => {
            return Err(in_flight_refusal(&cert.id));
        }
        (None, RenewalBudget::Unbounded) => None,
    };

    let config = AcmeConfig {
        staging: cert.issuer.contains("STAGING") || cert.issuer.contains("(staging)"),
        contact_email: None,
    };

    // In-place renewal : same id, route bindings untouched (AC1).
    let ordered = execute_renewal(
        state,
        &config,
        &renewal_domains(&cert),
        plan,
        Some(&cert.id),
    )
    .await;
    if let Err(e) = ordered {
        // The CA's refusal is the CA's, whoever asked: recording it
        // here is what keeps the loop and the next token away from
        // an identifier set the CA has already said no to.
        if let Some(until) = cooldown_from_error(&e.to_string(), Utc::now()) {
            state.renewals.record_cooldown(&cert.id, until);
        }
        return Err(ApiError::Internal(format!("ACME renewal failed: {e}")));
    }
    state.renewals.clear_cooldown(&cert.id);

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
    crate::audit::record(
        state,
        actor,
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

/// The 409 a token gets for a certificate whose order is open.
fn in_flight_refusal(id: &str) -> ApiError {
    ApiError::Conflict(format!(
        "certificate `{id}`: a renewal is in flight; one order per certificate at a time"
    ))
}

/// [`RenewalBudget::PerCertificate`], applied to `cert` at `now`:
/// nothing in flight for it, no CA cooldown on it, and its last
/// issuance at least [`MIN_TOKEN_RENEWAL_INTERVAL_HOURS`] ago.
///
/// Read off the row's own `not_before`, which every issuance path
/// writes as the order's instant. The refusal names the id and the
/// wait, never a hostname the token may not hold.
///
/// # Errors
///
/// `Conflict` for an open order, `RateLimitedBecause` for the interval
/// and for the cooldown, each carrying the seconds to wait.
fn ensure_token_renewal_budget(
    ledger: &RenewalLedger,
    cert: &lorica_config::models::Certificate,
    now: DateTime<Utc>,
) -> Result<(), ApiError> {
    if ledger.is_in_flight(&cert.id) {
        return Err(in_flight_refusal(&cert.id));
    }
    if let Some(until) = ledger.cooldown_until(&cert.id, now) {
        return Err(ApiError::RateLimitedBecause {
            retry_after_s: seconds_until(now, until),
            reason: format!(
                "certificate `{}`: the CA's rate limit refused an order for it; nothing is \
                 renewed until {until}",
                cert.id
            ),
        });
    }
    let interval = chrono::Duration::hours(MIN_TOKEN_RENEWAL_INTERVAL_HOURS);
    let open_again = cert.not_before + interval;
    if now < open_again {
        return Err(ApiError::RateLimitedBecause {
            retry_after_s: seconds_until(now, open_again),
            reason: format!(
                "certificate `{}` was issued less than {MIN_TOKEN_RENEWAL_INTERVAL_HOURS} hours \
                 ago; a token renews a certificate at most once in that many hours",
                cert.id
            ),
        });
    }
    Ok(())
}

/// The whole seconds from `now` to `until`, at least one.
fn seconds_until(now: DateTime<Utc>, until: DateTime<Utc>) -> u64 {
    u64::try_from((until - now).num_seconds())
        .unwrap_or(0)
        .max(1)
}

/// Every name a renewal orders: the primary and the SANs, deduplicated.
fn renewal_domains(cert: &lorica_config::models::Certificate) -> Vec<String> {
    let mut all_domains = vec![cert.domain.clone()];
    for d in &cert.san_domains {
        if !all_domains.contains(d) {
            all_domains.push(d.clone());
        }
    }
    all_domains
}

/// How a certificate is renewed, resolved from the row and its DNS
/// provider before any order is placed.
///
/// Resolved once and executed once, so the manual renewal's preview
/// refuses exactly what its apply would: before this the method and
/// the provider were resolved inside the call that also placed the
/// order, and a `dns01-manual` certificate previewed as "would renew"
/// and then failed on apply.
#[derive(Debug)]
enum RenewalPlan {
    /// HTTP-01, the method a row without `acme_method` gets.
    Http01,
    /// DNS-01 through a global DNS provider whose configuration parsed
    /// and matches the method's provider name.
    Dns01 {
        method: String,
        provider_id: Option<String>,
        config: DnsChallengeConfig,
    },
}

/// Resolve [`RenewalPlan`] for `cert`, given the DNS provider row its
/// `acme_dns_provider_id` names (`None` when it names none, or the row
/// is gone).
///
/// - `"http01"` or `None` -> HTTP-01 (original behavior)
/// - `"dns01-cloudflare"` / `"dns01-route53"` / `"dns01-ovh"` -> the
///   provider's configuration, checked against the method
/// - `"dns01-manual"` -> error (requires manual renewal)
///
/// # Errors
///
/// The reason the certificate cannot be renewed this way, in the words
/// the operator reads.
fn plan_renewal(
    cert: &lorica_config::models::Certificate,
    provider: Option<&lorica_config::models::DnsProvider>,
) -> Result<RenewalPlan, String> {
    let method = cert.acme_method.as_deref().unwrap_or("http01");

    match method {
        "http01" => Ok(RenewalPlan::Http01),
        "dns01-manual" => Err("manual DNS-01 certificates require manual renewal - \
             use the provision-dns-manual endpoint"
            .to_string()),
        m if m.starts_with("dns01-") => {
            // Extract provider name from "dns01-provider"
            let provider_name = &m[6..];

            let Some(pid) = cert.acme_dns_provider_id.as_deref() else {
                return Err(format!(
                    "certificate has method '{m}' but no DNS provider configured - \
                     cannot auto-renew"
                ));
            };
            let dp = provider.ok_or_else(|| {
                format!(
                    "certificate references DNS provider '{pid}' which no longer exists - \
                     cannot auto-renew"
                )
            })?;
            let config: DnsChallengeConfig = serde_json::from_str(&dp.config)
                .map_err(|e| format!("failed to parse DNS provider config: {e}"))?;

            // Verify provider matches
            if config.provider != provider_name {
                return Err(format!(
                    "DNS config provider '{}' does not match method '{m}'",
                    config.provider
                ));
            }
            Ok(RenewalPlan::Dns01 {
                method: m.to_string(),
                provider_id: Some(pid.to_string()),
                config,
            })
        }
        other => Err(format!("unknown ACME method: {other}")),
    }
}

/// Place the order `plan` describes.
///
/// `existing_cert_id` is threaded to the provisioning helpers so the
/// renewed leaf updates that row in place (same id) rather than
/// inserting a new certificate.
async fn execute_renewal(
    state: &AppState,
    config: &AcmeConfig,
    domains: &[String],
    plan: RenewalPlan,
    existing_cert_id: Option<&str>,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    match plan {
        RenewalPlan::Http01 => provision_with_acme(state, config, domains, existing_cert_id).await,
        RenewalPlan::Dns01 {
            method,
            provider_id,
            config: dns_config,
        } => {
            let challenger = build_dns_challenger(&dns_config)
                .await
                .map_err(|e| format!("failed to build DNS challenger for renewal: {e}"))?;

            provision_with_acme_dns(
                state,
                config,
                domains,
                challenger.as_ref(),
                &method,
                provider_id,
                existing_cert_id,
            )
            .await
        }
    }
}

/// Renew a certificate using the appropriate method based on
/// `acme_method`: the DNS provider read, the plan resolved, the order
/// placed. The background loop's one call; the manual renewal runs the
/// same three steps with the preview branch between the second and
/// the third.
async fn renew_with_method(
    state: &AppState,
    cert: &lorica_config::models::Certificate,
    config: &AcmeConfig,
    domains: &[String],
    existing_cert_id: Option<&str>,
) -> Result<String, Box<dyn std::error::Error + Send + Sync>> {
    let provider = match cert.acme_dns_provider_id.clone() {
        Some(pid) => {
            db_blocking(&state.store, move |store| {
                store.get_dns_provider(&pid).map_err(|e| {
                    ApiError::Internal(format!("failed to fetch DNS provider '{pid}': {e}"))
                })
            })
            .await?
        }
        None => None,
    };
    let plan = plan_renewal(cert, provider.as_ref())?;
    execute_renewal(state, config, domains, plan, existing_cert_id).await
}
