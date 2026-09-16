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
//! AC #2). The `reason` field of the `automation.request.unauthenticated`
//! row is the only place the precise cause is written: `wrong_alg`,
//! `unknown_kid`, `expired`, `bound_claim_mismatch:<claim>`,
//! `replayed`, `token_revoked` and the rest, so an operator can tell a
//! pipeline what to fix without the wire telling an attacker what to
//! try next.

use std::net::SocketAddr;
use std::sync::{Arc, OnceLock};

use axum::extract::{ConnectInfo, Request, State};
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

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

/// What the bearer gate decided about a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthOutcome {
    /// Authenticated; carries [`AutomationPrincipal::audit_identity`].
    Accepted(String),
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
        let _ = self
            .0
            .set(AuthOutcome::Accepted(principal.audit_identity()));
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
/// itself.
fn outcome(status: StatusCode) -> &'static str {
    match status {
        StatusCode::UNAUTHORIZED => "unauthenticated",
        StatusCode::FORBIDDEN => "forbidden",
        _ if status.is_success() => "ok",
        _ => "refused",
    }
}

/// Axum middleware recording one audit row per automation request.
pub async fn audit_automation_request(
    State(state): State<AppState>,
    mut req: Request,
    next: Next,
) -> Response {
    let method: String = req.method().to_string();
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
    // means something else. A refusal names nobody and carries its
    // reason in the payload instead.
    let (username, reason): (String, Option<serde_json::Value>) = match slot.get() {
        Some(AuthOutcome::Accepted(identity)) => (identity, None),
        Some(AuthOutcome::Refused(reason)) => (
            ANONYMOUS_PRINCIPAL.to_string(),
            Some(serde_json::json!({ "reason": reason })),
        ),
        None => (ANONYMOUS_PRINCIPAL.to_string(), None),
    };
    let ctx = AuditContext {
        username,
        role: AUTOMATION_ROLE.to_string(),
        ip,
        user_agent,
    };
    crate::audit::record(
        &state,
        &ctx,
        &format!("automation.request.{outcome_word}"),
        (AUTOMATION_TARGET_TYPE, &format!("{method} {path}")),
        None,
        reason.as_ref(),
    )
    .await;

    response
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_outcome_word_follows_the_status() {
        assert_eq!(outcome(StatusCode::OK), "ok");
        assert_eq!(outcome(StatusCode::NO_CONTENT), "ok");
        assert_eq!(outcome(StatusCode::UNAUTHORIZED), "unauthenticated");
        assert_eq!(outcome(StatusCode::FORBIDDEN), "forbidden");
        assert_eq!(outcome(StatusCode::NOT_FOUND), "refused");
        assert_eq!(outcome(StatusCode::INTERNAL_SERVER_ERROR), "refused");
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
}
