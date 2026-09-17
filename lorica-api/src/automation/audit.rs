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

//! Audit for the automation plane: EVERY request lands a row, not only
//! the mutations.
//!
//! The management plane audits mutations because a read there is a
//! human looking at a page they are already allowed to see. Here the
//! caller is a credential, and the questions after an incident are
//! "which token was this" and "what was it reaching for", which a
//! read answers as much as a write. Refusals are audited too: a token
//! that stopped working, or one presenting itself from an address
//! nobody expected, is exactly what an operator needs to see.
//!
//! "Every request" includes one whose handler panics: the panic net in
//! [`super::router::with_audit_and_panic_net`] sits directly inside
//! this layer and turns an unwind into a 500 that returns normally, so
//! the row is written in the case an operator most wants it.
//!
//! # How the outcome reaches this layer
//!
//! This middleware is the OUTERMOST layer, so it sees requests the
//! bearer gate refuses. But it therefore also loses the request
//! extensions by the time the response comes back, and the principal
//! is only known inside the gate. On the way down it installs a
//! [`PrincipalSlot`]; the gate fills it with the principal on a
//! successful authentication and with the precise reason on a
//! refusal, and this layer reads its own handle afterwards. The slot
//! is write-once, so a later layer cannot rewrite who the row names.
//!
//! # The reason lives here and nowhere else
//!
//! A refused request answers one generic 401 on the wire (Story 10.5
//! AC #2). The audit row is the only place the precise cause is
//! written: `wrong_alg`, `unknown_kid`, `expired`,
//! `bound_claim_mismatch:<claim>`, `replayed`, `token_revoked` and the
//! rest of [`AUTOMATION_AUDIT_REASONS`], so an operator can tell a
//! pipeline what to fix without the wire telling an attacker what to
//! try next.
//!
//! It is written where an operator LOOKS, which is two places and not
//! one. `GET /api/v1/audit` returns the row, so the reason rides in
//! the row's `action` (`automation.request.unauthenticated:wrong_alg`);
//! syslog, OTLP and the file log carry the `lorica::audit` event, so
//! `crate::audit` lifts the same text into a `reason` field. What it
//! is NOT written into is a payload: Story 9.9 hashes those because
//! they may carry secrets, and that rule is not weakened here. The
//! reason vocabulary is a closed list of words the node chooses, never
//! caller-supplied material, which is precisely why it may travel in
//! clear where a payload may not.
//!
//! # The row is queued, not written here
//!
//! [`crate::audit::record`] used to take the store lock and commit one
//! chained-hash row before the response returned, so a pipeline burst
//! serialised there at about one SQLite commit per request. It now
//! offers the row to the bounded, single-consumer queue described in
//! [`crate::audit`], which the management plane shares: the chain hash
//! is only meaningful in write order, so one consumer is the only
//! shape that works, and one queue for both planes is what keeps their
//! durability promise identical for the same table.
//!
//! What a refusal costs the caller is now a `try_send`. What it costs
//! an operator is that the row is durable within the consumer's next
//! drain rather than before the 401, and that a queue full for long
//! enough sheds rows into `lorica_audit_rows_dropped_total`.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;
use lorica_config::models::AutomationScope;

use super::auth::AutomationPrincipal;
use crate::audit::AuditContext;
use crate::server::AppState;

/// `operator_role` stamped on every automation row.
///
/// The management plane puts the RBAC role here. An automation
/// principal has no role, it has scopes, so the column names the plane
/// instead: an operator filtering the audit log on `automation` gets
/// every machine-driven request and nothing else.
pub(super) const AUTOMATION_ROLE: &str = "automation";

/// `target_type` stamped on every automation row.
const AUTOMATION_TARGET_TYPE: &str = "automation_request";

/// What `operator_username` says when the request never authenticated.
const ANONYMOUS_PRINCIPAL: &str = "-";

/// The reason a 403 carries when the path itself declares no scope.
///
/// Not a caller's mistake and not a token's: a route reachable through
/// this listener with no entry in the scope matrix. The scope gate
/// logs it at ERROR; the audit row says the same thing to whoever
/// reads the trail instead of the journal.
const NO_DECLARED_SCOPE: &str = "no_declared_scope";

/// Every reason an automation audit row can name, and the vocabulary
/// the "Reading a refusal" section of `docs/automation.md` publishes.
///
/// ONE list, because the alternative is three (the bearer gate, the
/// scope gate, the document) and three is three chances for an
/// operator to meet a word no table explains. The test below asserts
/// the gates emit nothing that is not here.
///
/// Two of these carry a parameter after a second colon:
/// `missing_claim:jti`, `bound_claim_mismatch:project_path`. The four
/// scope spellings are the reasons a 403 names, and they contain a
/// colon of their own, which is why membership is
/// [`is_published_reason`] and not a bare `contains`.
pub const AUTOMATION_AUDIT_REASONS: &[&str] = &[
    // The bearer gate, before either credential path.
    "no_bearer",
    "bearer_too_long",
    "not_a_credential",
    "store_error",
    // The static-token path.
    "token_unknown_or_wrong_secret",
    "token_revoked",
    "token_expired",
    // The ID-token path, before the verifier.
    "too_many_audiences",
    // The ID-token verifier (`super::oidc::RefusalReason`).
    "malformed",
    "wrong_alg",
    "no_issuer",
    "unknown_kid",
    "jwks_unavailable",
    "invalid_key",
    "bad_signature",
    "expired",
    "not_yet_valid",
    "wrong_aud",
    "wrong_iss",
    "missing_claim",
    "bound_claim_mismatch",
    "replayed",
    // The scope gate: the grant the token did not carry, or the path
    // that declares none.
    "environments:write",
    "environments:read",
    "routes:read",
    "certificates:read",
    NO_DECLARED_SCOPE,
];

/// Whether `reason` is in the published vocabulary: either a listed
/// word exactly, or a listed word carrying its parameter after a colon.
///
/// ```
/// use lorica_api::automation::audit::is_published_reason;
/// assert!(is_published_reason("wrong_alg"));
/// assert!(is_published_reason("bound_claim_mismatch:project_path"));
/// assert!(is_published_reason("environments:write"));
/// assert!(!is_published_reason("something_someone_invented"));
/// ```
pub fn is_published_reason(reason: &str) -> bool {
    AUTOMATION_AUDIT_REASONS.iter().any(|known| {
        reason == *known
            || reason
                .strip_prefix(known)
                .is_some_and(|rest| rest.starts_with(':'))
    })
}

/// What the bearer gate decided about a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Authenticated.
    Accepted {
        /// [`AutomationPrincipal::audit_identity`], what the row names.
        identity: String,
        /// The grant the credential carries. Kept so a 403 can say
        /// which scope was missing: the scope gate answers through the
        /// shared error type and this layer is outside it, so the only
        /// way to name the gap is to weigh the same two things the
        /// gate weighed.
        scopes: Vec<AutomationScope>,
    },
    /// Refused; carries the precise reason for the audit row.
    Refused(String),
}

/// Write-once handle the bearer gate uses to tell the audit layer who
/// the caller turned out to be, or why they were turned away.
///
/// Cloning shares the cell, which is the point: the audit layer keeps
/// one handle while the other travels down inside the request.
#[derive(Debug, Clone, Default)]
pub struct PrincipalSlot(Arc<OnceLock<AuthOutcome>>);

impl PrincipalSlot {
    /// Record the authenticated principal. The first write wins.
    pub fn accept(&self, principal: &AutomationPrincipal) {
        let _ = self.0.set(AuthOutcome::Accepted {
            identity: principal.audit_identity(),
            scopes: principal.scopes.clone(),
        });
    }

    /// Record why the request was refused. The first write wins.
    pub fn refuse(&self, reason: &str) {
        let _ = self.0.set(AuthOutcome::Refused(reason.to_string()));
    }

    /// The gate's decision, or `None` when the gate never ran.
    pub fn get(&self) -> Option<AuthOutcome> {
        self.0.get().cloned()
    }
}

/// The outcome word stamped into the action verb.
///
/// Derived from the status the chain produced rather than passed down,
/// so a future layer that refuses a request cannot forget to report
/// itself. A 5xx is `error` and not `refused`: the node broke, it did
/// not decide, and an operator scanning the trail for the node's own
/// faults must not have to read them out of the same bucket as the
/// requests it turned away on purpose.
fn outcome(status: StatusCode) -> &'static str {
    match status {
        StatusCode::UNAUTHORIZED => "unauthenticated",
        StatusCode::FORBIDDEN => "forbidden",
        _ if status.is_success() => "ok",
        _ if status.is_server_error() => "error",
        _ => "refused",
    }
}

/// The wire spelling of a scope, matching its serde rename so an
/// operator reads the same string in the audit row, in the 403 body
/// and in the token.
///
/// [`super::scope`] has the same four arms for the error body. One
/// copy here beats exporting a private helper to build one const: the
/// test below asserts both spell what serde does, which is the thing
/// that must not drift.
fn scope_wire_name(scope: AutomationScope) -> &'static str {
    match scope {
        AutomationScope::EnvironmentsWrite => "environments:write",
        AutomationScope::EnvironmentsRead => "environments:read",
        AutomationScope::RoutesRead => "routes:read",
        AutomationScope::CertificatesRead => "certificates:read",
    }
}

/// The reason to spell into the action verb, or `None` when the
/// outcome needs no explaining.
///
/// A 401 knows its own reason: the bearer gate wrote it into the slot.
/// A 403 does not, so it is recovered from the same matrix the scope
/// gate consulted, and only when the credential really lacks what the
/// path wanted. A 403 a HANDLER raised (an ownership rule, a hostname
/// outside the grant) names no scope on purpose: naming the path's
/// scope there would send an operator off to re-mint a token that was
/// never the problem.
fn refusal_reason(
    status: StatusCode,
    decision: Option<&AuthOutcome>,
    method: &Method,
    path: &str,
) -> Option<String> {
    match (status, decision) {
        (StatusCode::UNAUTHORIZED, Some(AuthOutcome::Refused(reason))) => Some(reason.clone()),
        (StatusCode::FORBIDDEN, Some(AuthOutcome::Accepted { scopes, .. })) => {
            match super::scope::required_scope(method, path) {
                None => Some(NO_DECLARED_SCOPE.to_string()),
                Some(needed) if !scopes.contains(&needed) => {
                    Some(scope_wire_name(needed).to_string())
                }
                Some(_) => None,
            }
        }
        _ => None,
    }
}

/// The action verb for one request.
///
/// The reason rides INSIDE the verb rather than beside it because
/// `GET /api/v1/audit` returns the stored row, and of the row's
/// columns only `action` is both free-form and indexed: an operator
/// filtering on `automation.request.unauthenticated` still sees every
/// refusal, and now reads the cause without a second query.
fn action_for(outcome_word: &str, reason: Option<&str>) -> String {
    match reason {
        Some(reason) => format!("automation.request.{outcome_word}:{reason}"),
        None => format!("automation.request.{outcome_word}"),
    }
}

/// Axum middleware recording one audit row per automation request.
pub async fn audit_automation_request(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let method: Method = req.method().clone();
    let path: String = req.uri().path().to_string();
    let ip: String = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map(|info| info.0.ip().to_string())
        .unwrap_or_default();
    let user_agent: String = req
        .headers()
        .get(header::USER_AGENT)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_default()
        .to_string();

    let slot = PrincipalSlot::default();
    req.extensions_mut().insert(slot.clone());

    let response = next.run(req).await;

    // Counted from the same word the audit row gets, so the scrape and
    // the log never disagree on what a request was.
    let outcome_word: &'static str = outcome(response.status());
    crate::metrics::inc_automation_request(outcome_word);

    // The principal's two halves share one column because the audit
    // row has one principal field and an automation principal has two
    // identities: the label an operator reads, and the id they revoke.
    // Splitting them would put one of them in a column that already
    // means something else. A refusal names nobody, and carries its
    // reason in the action verb instead.
    let decision = slot.get();
    let username: String = match &decision {
        Some(AuthOutcome::Accepted { identity, .. }) => identity.clone(),
        _ => ANONYMOUS_PRINCIPAL.to_string(),
    };
    let reason: Option<String> =
        refusal_reason(response.status(), decision.as_ref(), &method, &path);

    let ctx = AuditContext {
        username,
        role: AUTOMATION_ROLE.to_string(),
        ip,
        user_agent,
    };
    // No `after` payload: it used to hold the reason, which the action
    // verb now carries in clear. A hash of one of two dozen known
    // words was never a secret, and a column an operator cannot read
    // is not worth the row it sits in.
    crate::audit::record(
        &state,
        &ctx,
        &action_for(outcome_word, reason.as_deref()),
        (AUTOMATION_TARGET_TYPE, &format!("{method} {path}")),
        None,
        None,
    )
    .await;

    response
}

#[cfg(test)]
mod tests {
    use std::sync::Mutex;
    use std::time::Instant;

    use axum::body::Body;
    use axum::routing::get;
    use axum::Router;
    use http::Request as HttpRequest;
    use tower::ServiceExt;

    use super::*;
    use crate::audit::AuditQuery;
    use crate::automation::oidc::RefusalReason;
    use crate::logs::LogBuffer;
    use crate::metrics::gathered_counter;
    use crate::server::Mode;
    use crate::system::SystemCache;

    const REQUESTS: &str = "lorica_automation_requests_total";

    #[test]
    fn the_outcome_word_follows_the_status() {
        assert_eq!(outcome(StatusCode::OK), "ok");
        assert_eq!(outcome(StatusCode::NO_CONTENT), "ok");
        assert_eq!(outcome(StatusCode::UNAUTHORIZED), "unauthenticated");
        assert_eq!(outcome(StatusCode::FORBIDDEN), "forbidden");
        assert_eq!(outcome(StatusCode::NOT_FOUND), "refused");
        // The node's own fault reads as its own word.
        assert_eq!(outcome(StatusCode::INTERNAL_SERVER_ERROR), "error");
        assert_eq!(outcome(StatusCode::SERVICE_UNAVAILABLE), "error");
    }

    #[test]
    fn the_principal_slot_is_write_once() {
        let slot = PrincipalSlot::default();
        assert_eq!(slot.get(), None);
        slot.refuse("wrong_alg");
        slot.refuse("expired");
        assert_eq!(
            slot.get(),
            Some(AuthOutcome::Refused("wrong_alg".to_string()))
        );
    }

    // ---- the published vocabulary ----

    /// Every reason literal the bearer gate hands to the slot.
    ///
    /// Read out of the gate's own source, which is the only way to
    /// couple this list to a file this module does not own: a reason
    /// added there and not published here fails the test below instead
    /// of reaching an operator as a word no table explains.
    fn reasons_spelled_in_the_bearer_gate(source: &str) -> Vec<&str> {
        // The gate's own tests spell refusals too, and a test fixture
        // is not something an operator ever reads.
        let source = source.split("#[cfg(test)]").next().unwrap_or(source);
        source
            .match_indices("Err(\"")
            .filter_map(|(at, marker)| {
                let rest = &source[at + marker.len()..];
                rest.split_once('"').map(|(reason, _)| reason)
            })
            .collect()
    }

    #[test]
    fn every_reason_the_bearer_gate_can_emit_is_published() {
        let gate = include_str!("auth.rs");
        let spelled = reasons_spelled_in_the_bearer_gate(gate);
        // Cheap guard against the scan silently matching nothing the
        // day the gate is rewritten in another shape.
        assert!(
            spelled.len() >= 7,
            "the bearer gate's reason literals were not found: {spelled:?}"
        );
        for reason in spelled {
            assert!(
                is_published_reason(reason),
                "`{reason}` is emitted by the bearer gate and is not in AUTOMATION_AUDIT_REASONS"
            );
        }
        // `no_bearer` is passed to `refuse` directly rather than
        // through an `Err`, so the scan above does not see it.
        assert!(is_published_reason("no_bearer"));
    }

    #[test]
    fn every_reason_the_id_token_verifier_can_emit_is_published() {
        let every_variant = [
            RefusalReason::Malformed,
            RefusalReason::WrongAlg,
            RefusalReason::NoIssuer,
            RefusalReason::UnknownKid,
            RefusalReason::JwksUnavailable,
            RefusalReason::InvalidKey,
            RefusalReason::BadSignature,
            RefusalReason::Expired,
            RefusalReason::NotYetValid,
            RefusalReason::WrongAud,
            RefusalReason::WrongIss,
            RefusalReason::MissingClaim("jti".to_string()),
            RefusalReason::BoundClaimMismatch("environment_protected".to_string()),
            RefusalReason::Replayed,
        ];
        for variant in &every_variant {
            // Exhaustive on purpose: a new variant stops compiling
            // here, before it can reach a row as an unpublished word.
            match variant {
                RefusalReason::Malformed
                | RefusalReason::WrongAlg
                | RefusalReason::NoIssuer
                | RefusalReason::UnknownKid
                | RefusalReason::JwksUnavailable
                | RefusalReason::InvalidKey
                | RefusalReason::BadSignature
                | RefusalReason::Expired
                | RefusalReason::NotYetValid
                | RefusalReason::WrongAud
                | RefusalReason::WrongIss
                | RefusalReason::MissingClaim(_)
                | RefusalReason::BoundClaimMismatch(_)
                | RefusalReason::Replayed => {}
            }
            let reason = variant.audit_reason();
            assert!(
                is_published_reason(&reason),
                "`{reason}` is emitted by the verifier and is not in AUTOMATION_AUDIT_REASONS"
            );
        }
    }

    #[test]
    fn every_scope_spells_itself_the_way_the_wire_does_and_is_published() {
        for scope in [
            AutomationScope::EnvironmentsWrite,
            AutomationScope::EnvironmentsRead,
            AutomationScope::RoutesRead,
            AutomationScope::CertificatesRead,
        ] {
            let wire = scope_wire_name(scope);
            assert_eq!(
                serde_json::to_string(&scope).expect("a scope serialises"),
                format!("\"{wire}\"")
            );
            assert!(is_published_reason(wire));
        }
    }

    #[test]
    fn the_longest_action_a_refusal_can_write_stays_short() {
        // `action` is SQLite TEXT with no length cap, so this is a
        // readability bound rather than a storage one: the longest
        // verb is still one line in a terminal.
        let longest = action_for(
            "unauthenticated",
            Some(
                &RefusalReason::BoundClaimMismatch("environment_protected".to_string())
                    .audit_reason(),
            ),
        );
        assert_eq!(
            longest,
            "automation.request.unauthenticated:bound_claim_mismatch:environment_protected"
        );
        assert_eq!(longest.len(), 77);
    }

    #[test]
    fn a_403_names_the_missing_scope_and_nothing_when_a_handler_raised_it() {
        let holds_read = AuthOutcome::Accepted {
            identity: "ci".to_string(),
            scopes: vec![AutomationScope::EnvironmentsRead],
        };
        // The scope gate refused: the verb names the grant the token
        // did not carry.
        assert_eq!(
            refusal_reason(
                StatusCode::FORBIDDEN,
                Some(&holds_read),
                &Method::PUT,
                "/automation/v1/environments/pr-42"
            )
            .as_deref(),
            Some("environments:write")
        );
        // A handler refused a token that DOES carry the scope: naming
        // it would send an operator to re-mint a working token.
        assert_eq!(
            refusal_reason(
                StatusCode::FORBIDDEN,
                Some(&holds_read),
                &Method::GET,
                "/automation/v1/environments/pr-42"
            ),
            None
        );
        // A path with no entry in the matrix says so.
        assert_eq!(
            refusal_reason(
                StatusCode::FORBIDDEN,
                Some(&holds_read),
                &Method::GET,
                "/automation/v1/tokens"
            )
            .as_deref(),
            Some(NO_DECLARED_SCOPE)
        );
        // A success explains nothing.
        assert_eq!(
            refusal_reason(
                StatusCode::OK,
                Some(&holds_read),
                &Method::GET,
                "/automation/v1/whoami"
            ),
            None
        );
    }

    // ---- through the real layer stack ----

    /// Collects the `action` and `reason` fields of every
    /// `lorica::audit` event, without a subscriber crate: `lorica-api`
    /// does not depend on `tracing-subscriber` and this is not worth
    /// one.
    #[derive(Default)]
    struct AuditEventTap {
        seen: Mutex<Vec<TappedEvent>>,
    }

    #[derive(Debug, Default, PartialEq, Eq)]
    struct TappedEvent {
        action: String,
        reason: String,
        target_id: String,
    }

    impl tracing::field::Visit for TappedEvent {
        fn record_debug(&mut self, field: &tracing::field::Field, value: &dyn std::fmt::Debug) {
            match field.name() {
                "action" => self.action = format!("{value:?}"),
                "reason" => self.reason = format!("{value:?}"),
                "target_id" => self.target_id = format!("{value:?}"),
                _ => {}
            }
        }
    }

    struct TapSubscriber(Arc<AuditEventTap>);

    impl tracing::Subscriber for TapSubscriber {
        fn enabled(&self, metadata: &tracing::Metadata<'_>) -> bool {
            metadata.target() == "lorica::audit"
        }

        /// Explicit, because the global max level is what the `info!`
        /// macro checks before it builds anything: no hint would leave
        /// it wherever the rest of the binary left it.
        fn max_level_hint(&self) -> Option<tracing::level_filters::LevelFilter> {
            Some(tracing::level_filters::LevelFilter::TRACE)
        }

        fn new_span(&self, _attrs: &tracing::span::Attributes<'_>) -> tracing::Id {
            tracing::Id::from_u64(1)
        }

        fn record(&self, _id: &tracing::Id, _values: &tracing::span::Record<'_>) {}

        fn record_follows_from(&self, _id: &tracing::Id, _follows: &tracing::Id) {}

        fn event(&self, event: &tracing::Event<'_>) {
            if event.metadata().target() != "lorica::audit" {
                return;
            }
            let mut tapped = TappedEvent::default();
            event.record(&mut tapped);
            if let Ok(mut seen) = self.0.seen.lock() {
                seen.push(tapped);
            }
        }

        fn enter(&self, _id: &tracing::Id) {}

        fn exit(&self, _id: &tracing::Id) {}
    }

    /// The process-wide audit-event tap, installed on first use.
    ///
    /// A scoped subscriber would be tidier and does not work here.
    /// Callsite interest and the global max level are process-wide
    /// state cached on first use, and the eight hundred other tests in
    /// this binary run with no subscriber at all, so a guard installed
    /// mid-run races them: the `lorica::audit` callsite is sometimes
    /// already cached as "nobody is listening" and the event is never
    /// built. Installed once as the global default, before any request
    /// this test makes, it is deterministic. The tap therefore sees
    /// every test's audit events, which is why the assertion filters
    /// on a `target_id` no other test uses.
    fn audit_event_tap() -> &'static Arc<AuditEventTap> {
        static TAP: OnceLock<Arc<AuditEventTap>> = OnceLock::new();
        TAP.get_or_init(|| {
            let tap = Arc::new(AuditEventTap::default());
            let _ = tracing::subscriber::set_global_default(TapSubscriber(Arc::clone(&tap)));
            tap
        })
    }

    fn test_state(log_store: Arc<crate::log_store::LogStore>) -> AppState {
        let store = lorica_config::ConfigStore::open_in_memory().expect("test setup: store opens");
        AppState {
            store: Arc::new(tokio::sync::Mutex::new(store)),
            log_buffer: Arc::new(LogBuffer::new(100)),
            system_cache: Arc::new(tokio::sync::Mutex::new(SystemCache::new())),
            active_connections: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            started_at: Instant::now(),
            data_dir: std::path::PathBuf::from("/var/lib/lorica"),
            http_port: 8080,
            https_port: 8443,
            config_reload_tx: None,
            mode: Mode::Test,
            waf_event_buffer: None,
            waf_engine: None,
            waf_rule_count: None,
            acme_challenge_store: None,
            pending_dns_challenges: Arc::new(dashmap::DashMap::new()),
            sla_collector: None,
            load_test_engine: None,
            notification_history: None,
            log_store: Some(log_store),
            log_writer: None,
            task_tracker: tokio_util::task::TaskTracker::new(),
            cluster: crate::cluster::ClusterRuntime::Standalone,
            oidc: crate::automation::oidc::test_support::verifier_without_issuer(),
        }
    }

    /// Every automation row in the store, newest first.
    ///
    /// Flushes first: the layer only enqueues the row, so it is
    /// durable within the audit writer's next drain and not when the
    /// response came back.
    async fn automation_rows(
        log_store: &crate::log_store::LogStore,
    ) -> Vec<crate::audit::AuditRecord> {
        log_store
            .flush_audit()
            .await
            .expect("the audit writer drains");
        let (rows, _) = log_store
            .query_audit(&AuditQuery {
                action_prefix: Some("automation.request.".to_string()),
                limit: 50,
                ..AuditQuery::default()
            })
            .expect("the audit query runs");
        rows
    }

    #[tokio::test]
    async fn a_refusal_lands_a_row_whose_action_names_the_reason_and_an_event_carrying_it() {
        let dir = tempfile::tempdir().expect("test setup: temp dir");
        let log_store =
            Arc::new(crate::log_store::LogStore::open(dir.path()).expect("test setup: log store"));
        let state = test_state(Arc::clone(&log_store));
        let router = crate::automation::build_automation_router(state);

        // A path no other test asks for, because the tap is shared by
        // the whole binary and `target_id` is what tells this
        // request's event from everyone else's. The bearer gate
        // refuses before routing, so the path need not exist.
        const PROBE: &str = "/automation/v1/environments/audit-reason-probe";
        let tap = audit_event_tap();
        let response = router
            .oneshot(
                HttpRequest::builder()
                    .method(Method::GET)
                    .uri(PROBE)
                    .header(header::AUTHORIZATION, "Bearer definitely-not-a-credential")
                    .body(Body::empty())
                    .expect("test setup: request builds"),
            )
            .await
            .expect("test setup: request runs");
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);

        // 1. The stored row, which is what `GET /api/v1/audit` returns.
        let rows = automation_rows(&log_store).await;
        assert_eq!(rows.len(), 1, "one row per request: {rows:?}");
        assert_eq!(
            rows[0].action,
            "automation.request.unauthenticated:not_a_credential"
        );
        assert_eq!(rows[0].operator_username, ANONYMOUS_PRINCIPAL);
        assert_eq!(rows[0].operator_role, AUTOMATION_ROLE);

        // 2. The tracing event, which is what syslog and OTLP carry.
        let seen = tap.seen.lock().expect("the tap lock holds");
        let mine: Vec<&TappedEvent> = seen
            .iter()
            .filter(|event| event.target_id == format!("GET {PROBE}"))
            .collect();
        assert_eq!(mine.len(), 1, "one event for this request: {seen:?}");
        assert_eq!(
            mine[0].action,
            "automation.request.unauthenticated:not_a_credential"
        );
        assert_eq!(mine[0].reason, "not_a_credential");
    }

    /// The bug this stands in for: any handler that unwinds. Named
    /// rather than a closure so the return type is a real one and not
    /// the never type.
    async fn a_handler_that_unwinds() -> &'static str {
        panic!("a handler that unwinds")
    }

    #[tokio::test]
    async fn a_panicking_handler_answers_500_and_still_lands_a_row() {
        let dir = tempfile::tempdir().expect("test setup: temp dir");
        let log_store =
            Arc::new(crate::log_store::LogStore::open(dir.path()).expect("test setup: log store"));
        let state = test_state(Arc::clone(&log_store));

        // The production router mounts no panicking handler, so the
        // test supplies one; the layer pair under it is the real one,
        // built by the same function `build_automation_router` calls.
        let router = crate::automation::router::with_audit_and_panic_net(
            Router::new().route("/automation/v1/panic", get(a_handler_that_unwinds)),
            state,
        );

        let before = gathered_counter(REQUESTS, &[("outcome", "error")]);
        let response = router
            .oneshot(
                HttpRequest::builder()
                    .method(Method::GET)
                    .uri("/automation/v1/panic")
                    .body(Body::empty())
                    .expect("test setup: request builds"),
            )
            .await
            .expect("the panic never reaches the caller as a broken connection");

        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
        let rows = automation_rows(&log_store).await;
        assert_eq!(rows.len(), 1, "the row an operator most wants: {rows:?}");
        assert_eq!(rows[0].action, "automation.request.error");
        assert!(gathered_counter(REQUESTS, &[("outcome", "error")]) > before);
    }
}
