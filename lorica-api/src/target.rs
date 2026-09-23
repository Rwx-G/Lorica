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

//! Who may act on the row a write names (Story 11.2).
//!
//! # The grant bounds the target, not only the claim
//!
//! The automation plane's write handlers check the token's grants
//! against what a body CLAIMS: the hostname a route write names, the
//! address a backend write points at. A write that names a row by id
//! claims nothing in its body and reaches the row all the same, so a
//! token granted `*.review.example.com` would have disabled the WAF on
//! a production route, drained a production backend or renewed any
//! certificate on the node. The guards here are how the `_as` bodies
//! hold the row itself to the same grant.
//!
//! # Why the check runs inside the store closure
//!
//! A guard is handed to the `_as` body and run by it inside the
//! `db_blocking` closure that performs the write, on the row that
//! closure just read and is about to write. The alternative, a check
//! in the handler before the body runs, reads one row and writes
//! another: anything between the two, a rename, a re-mark, a delete
//! and re-create under the same id, is a window. Here there is none.
//!
//! # Who builds one
//!
//! The management wrappers pass an unbounded guard: the session's role
//! was checked at the door and an operator reaches every row. The
//! automation handlers build a bounded one from the token, in
//! `crate::automation::write`, which is the one place the grant rules
//! are spelled. This module knows the shape of a guard and nothing of
//! the rules, so `routes::crud`, `backends` and `acme::renewal` depend
//! on no automation type.

use std::sync::Arc;

use lorica_config::models::{Backend, Certificate, Route};
use lorica_config::ConfigStore;

use crate::error::ApiError;

/// The rows a route write reads and would write, as its guard sees
/// them.
#[derive(Debug, Clone, Copy)]
pub struct RouteTarget<'a> {
    /// The row as stored now; `None` on a create.
    pub before: Option<&'a Route>,
    /// The row as it would be stored; `None` on a delete.
    pub after: Option<&'a Route>,
    /// The backend ids the write links at the top level: every one on
    /// a create, the patch's list when it carries one, `None` when the
    /// links are left alone.
    pub backend_ids: Option<&'a [String]>,
}

type RouteCheck = Arc<dyn Fn(&ConfigStore, RouteTarget<'_>) -> Result<(), ApiError> + Send + Sync>;
type BackendCheck = Arc<dyn Fn(&ConfigStore, &Backend) -> Result<(), ApiError> + Send + Sync>;
type CertificateCheck = Arc<dyn Fn(&Certificate) -> Result<(), ApiError> + Send + Sync>;

/// Who may act on a route row.
#[derive(Clone)]
pub struct RouteGuard(Option<RouteCheck>);

impl RouteGuard {
    /// Every row is reachable: the management plane, whose session's
    /// role was checked at the door.
    pub fn unbounded() -> Self {
        Self(None)
    }

    /// Only the rows `check` accepts are reachable.
    pub fn bounded(
        check: impl Fn(&ConfigStore, RouteTarget<'_>) -> Result<(), ApiError> + Send + Sync + 'static,
    ) -> Self {
        Self(Some(Arc::new(check)))
    }

    /// Run the check, inside the store closure that writes the row.
    ///
    /// # Errors
    ///
    /// Whatever the check refuses with, a `Forbidden` for a grant.
    pub fn check(&self, store: &ConfigStore, target: RouteTarget<'_>) -> Result<(), ApiError> {
        match &self.0 {
            Some(check) => check(store, target),
            None => Ok(()),
        }
    }
}

impl std::fmt::Debug for RouteGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() {
            "RouteGuard::bounded"
        } else {
            "RouteGuard::unbounded"
        })
    }
}

/// Who may act on a backend row.
#[derive(Clone)]
pub struct BackendGuard(Option<BackendCheck>);

impl BackendGuard {
    /// Every row is reachable.
    pub fn unbounded() -> Self {
        Self(None)
    }

    /// Only the rows `check` accepts are reachable.
    pub fn bounded(
        check: impl Fn(&ConfigStore, &Backend) -> Result<(), ApiError> + Send + Sync + 'static,
    ) -> Self {
        Self(Some(Arc::new(check)))
    }

    /// Run the check on a row, the one stored or the one about to be,
    /// inside the store closure that writes it.
    ///
    /// # Errors
    ///
    /// Whatever the check refuses with, a `Forbidden` for a grant.
    pub fn check(&self, store: &ConfigStore, backend: &Backend) -> Result<(), ApiError> {
        match &self.0 {
            Some(check) => check(store, backend),
            None => Ok(()),
        }
    }
}

impl std::fmt::Debug for BackendGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() {
            "BackendGuard::bounded"
        } else {
            "BackendGuard::unbounded"
        })
    }
}

/// Who may act on a certificate row.
#[derive(Clone)]
pub struct CertificateGuard(Option<CertificateCheck>);

impl CertificateGuard {
    /// Every row is reachable.
    pub fn unbounded() -> Self {
        Self(None)
    }

    /// Only the rows `check` accepts are reachable.
    pub fn bounded(
        check: impl Fn(&Certificate) -> Result<(), ApiError> + Send + Sync + 'static,
    ) -> Self {
        Self(Some(Arc::new(check)))
    }

    /// Run the check on the stored row.
    ///
    /// # Errors
    ///
    /// Whatever the check refuses with, a `Forbidden` for a grant.
    pub fn check(&self, certificate: &Certificate) -> Result<(), ApiError> {
        match &self.0 {
            Some(check) => check(certificate),
            None => Ok(()),
        }
    }
}

impl std::fmt::Debug for CertificateGuard {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(if self.0.is_some() {
            "CertificateGuard::bounded"
        } else {
            "CertificateGuard::unbounded"
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_unbounded_guard_accepts_and_a_bounded_one_answers_its_check() {
        let refused = RouteGuard::bounded(|_store, target| {
            let id = target.before.map_or("none", |route| route.id.as_str());
            Err(ApiError::Forbidden(format!("route `{id}` is not yours")))
        });
        assert_eq!(format!("{refused:?}"), "RouteGuard::bounded");
        assert_eq!(
            format!("{:?}", RouteGuard::unbounded()),
            "RouteGuard::unbounded"
        );
        assert_eq!(
            format!("{:?}", BackendGuard::unbounded()),
            "BackendGuard::unbounded"
        );
        assert_eq!(
            format!("{:?}", CertificateGuard::unbounded()),
            "CertificateGuard::unbounded"
        );
        let refused = CertificateGuard::bounded(|certificate| {
            Err(ApiError::Forbidden(format!(
                "certificate `{}` is not yours",
                certificate.id
            )))
        });
        let certificate = Certificate {
            id: "c-1".to_string(),
            domain: "a.example.com".to_string(),
            san_domains: Vec::new(),
            fingerprint: String::new(),
            cert_pem: String::new(),
            key_pem: String::new(),
            issuer: String::new(),
            not_before: chrono::Utc::now(),
            not_after: chrono::Utc::now(),
            is_acme: true,
            acme_auto_renew: true,
            created_at: chrono::Utc::now(),
            acme_method: None,
            acme_dns_provider_id: None,
        };
        assert!(matches!(
            refused.check(&certificate),
            Err(ApiError::Forbidden(message)) if message.contains("c-1")
        ));
        assert!(CertificateGuard::unbounded().check(&certificate).is_ok());
        let _ = Backend {
            id: "b-1".to_string(),
            address: "10.0.0.10:8080".to_string(),
            name: String::new(),
            group_name: String::new(),
            weight: 1,
            health_status: lorica_config::models::HealthStatus::Unknown,
            health_check_enabled: false,
            health_check_interval_s: 10,
            health_check_path: None,
            lifecycle_state: lorica_config::models::LifecycleState::Normal,
            active_connections: 0,
            tls_upstream: false,
            tls_skip_verify: false,
            tls_sni: None,
            h2_upstream: false,
            managed_by: None,
            created_at: chrono::Utc::now(),
            updated_at: chrono::Utc::now(),
        };
    }
}
