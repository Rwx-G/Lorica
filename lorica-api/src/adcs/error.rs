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

//! What the AD CS endpoints answer when they refuse or fail, and the
//! words a failure names its step with.
//!
//! # One condition, one answer
//!
//! A condition that stops an AD CS operation answers the same status and
//! code on every endpoint that meets it: the connection test, issuance,
//! "Renew now", adoption, reversion and the authority writes. Every code
//! is in [`ADCS_CODES`], and every handler builds its refusal from an
//! entry of it with [`AdcsCode::error`], so a client recognises a
//! condition without knowing which endpoint it called.
//!
//! On a follower every AD CS write is refused by the follower read-only
//! gate before it reaches a handler, with the gate's 409 `conflict`; the
//! handlers refuse with the same answer during a break-glass window
//! ([`refuse_on_follower`]), so a follower's refusal reads the same
//! either way.
//!
//! # Steps
//!
//! A failure names the step it happened at: the client's steps are
//! [`lorica_adcs::FailureStep`], and what happens around the client
//! (an issued certificate Lorica refused, a pending answer, a renewal
//! that could not build its request) is [`IssuanceStep`]. The two
//! vocabularies share no word, and audit rows, alerts and the dashboard
//! key on both.

use axum::http::StatusCode;

use super::runtime::NotRun;
use crate::cluster::ClusterRuntime;
use crate::error::ApiError;
use crate::server::AppState;

/// One refusal or failure an AD CS endpoint answers with a code of its
/// own.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AdcsCode {
    /// The envelope's `code`.
    pub code: &'static str,
    /// The HTTP status every endpoint answers it with.
    pub status: StatusCode,
    /// What it means, for the documentation and the dashboard.
    pub meaning: &'static str,
}

impl AdcsCode {
    /// This refusal with `message`.
    pub(crate) fn error(self, message: impl Into<String>) -> ApiError {
        ApiError::coded(self.status, self.code, message)
    }

    /// This failure with `message`, naming the step it happened at.
    pub(crate) fn error_at(self, step: &str, message: impl Into<String>) -> ApiError {
        ApiError::Coded {
            status: self.status,
            code: self.code,
            message: message.into(),
            step: Some(step.to_string()),
        }
    }
}

/// No authority is configured, or it has no password.
pub const NOT_CONFIGURED: AdcsCode = AdcsCode {
    code: "adcs_not_configured",
    status: StatusCode::CONFLICT,
    meaning: "No AD CS authority is configured, or it has no service account password",
};

/// The authority does not know its issuing CA certificate.
pub const NO_ISSUING_CA: AdcsCode = AdcsCode {
    code: "adcs_no_issuing_ca",
    status: StatusCode::CONFLICT,
    meaning: "The authority does not know its issuing CA certificate, so no certificate can be \
              verified as its own",
};

/// The authority is in the D15 failed state.
pub const FAILED_STATE: AdcsCode = AdcsCode {
    code: "adcs_failed_state",
    status: StatusCode::CONFLICT,
    meaning: "The KDC rejected the service account's credential; every AD CS operation is \
              suspended until a SuperAdmin saves a new password",
};

/// Another AD CS operation holds the single-flight guard.
pub const BUSY: AdcsCode = AdcsCode {
    code: "adcs_busy",
    status: StatusCode::CONFLICT,
    meaning: "Another AD CS operation is running",
};

/// A name of the request is refused (D5).
pub const SAN_REFUSED: AdcsCode = AdcsCode {
    code: "adcs_san_refused",
    status: StatusCode::UNPROCESSABLE_ENTITY,
    meaning: "A requested name is a wildcard, is not under an allowed suffix, or the list is \
              empty or too long",
};

/// The template of the request is not one the authority allows (D17).
pub const TEMPLATE_REFUSED: AdcsCode = AdcsCode {
    code: "adcs_template_refused",
    status: StatusCode::UNPROCESSABLE_ENTITY,
    meaning: "The requested template is not one the authority allows",
};

/// The authority denied the request.
pub const DENIED: AdcsCode = AdcsCode {
    code: "adcs_denied",
    status: StatusCode::UNPROCESSABLE_ENTITY,
    meaning: "The authority denied the request under its policy",
};

/// A fault of the authority, a client failure, or an issued certificate
/// Lorica refused.
pub const FAILED: AdcsCode = AdcsCode {
    code: "adcs_error",
    status: StatusCode::BAD_GATEWAY,
    meaning: "The authority answered with a fault, a step of the exchange failed, or the issued \
              certificate was refused; error.step names the step",
};

/// The generated `krb5.conf` could not be written.
pub const KRB5_CONF: AdcsCode = AdcsCode {
    code: "adcs_krb5_conf",
    status: StatusCode::INTERNAL_SERVER_ERROR,
    meaning: "The generated krb5.conf could not be written; the log names the path and the cause",
};

/// A certificate is not a candidate for adoption (D9).
pub const NOT_CANDIDATE: AdcsCode = AdcsCode {
    code: "adcs_not_candidate",
    status: StatusCode::UNPROCESSABLE_ENTITY,
    meaning: "The certificate is not manual, was not signed by the issuing CA, or has a name a \
              renewal could not request",
};

/// The PEM, key or domain of an AD CS certificate cannot be replaced.
pub const CERTIFICATE_MANAGED: AdcsCode = AdcsCode {
    code: "adcs_certificate_managed",
    status: StatusCode::CONFLICT,
    meaning: "An AD CS certificate's PEM, key and domain cannot be replaced; revert it to manual \
              first",
};

/// The private key of an AD CS certificate is never handed out (D16).
pub const KEY_NOT_EXPORTABLE: AdcsCode = AdcsCode {
    code: "adcs_key_not_exportable",
    status: StatusCode::FORBIDDEN,
    meaning: "The private key of an AD CS certificate never leaves Lorica",
};

/// A token asked to renew an AD CS certificate (D6).
pub const NOT_ON_AUTOMATION_PLANE: AdcsCode = AdcsCode {
    code: "adcs_renewal_not_on_automation_plane",
    status: StatusCode::FORBIDDEN,
    meaning: "AD CS certificates are renewed by the background loop and the dashboard only, \
              never by a token",
};

/// The operation outlived the handler's deadline and keeps running.
pub const STILL_RUNNING: AdcsCode = AdcsCode {
    code: "gateway_timeout",
    status: StatusCode::GATEWAY_TIMEOUT,
    meaning: "The operation outlived the request and is still finishing; its outcome is \
              audited when it ends",
};

/// Every code an AD CS endpoint answers with, besides the generic ones
/// (`conflict` on a follower, `not_found`, `unprocessable_entity` for a
/// malformed field, `internal_error`).
pub const ADCS_CODES: [AdcsCode; 14] = [
    NOT_CONFIGURED,
    NO_ISSUING_CA,
    FAILED_STATE,
    BUSY,
    SAN_REFUSED,
    TEMPLATE_REFUSED,
    DENIED,
    FAILED,
    KRB5_CONF,
    NOT_CANDIDATE,
    CERTIFICATE_MANAGED,
    KEY_NOT_EXPORTABLE,
    NOT_ON_AUTOMATION_PLANE,
    STILL_RUNNING,
];

/// The message of every refusal by the single-flight guard.
pub(crate) const BUSY_MESSAGE: &str =
    "an AD CS operation is already running; try again once it has finished";

/// The message of the 504 a handler answers when its operation outlives
/// the handler's deadline.
pub(crate) const STILL_RUNNING_MESSAGE: &str = "the AD CS operation is still finishing: a \
     Kerberos exchange outlived the operation timeout. Its outcome is recorded in the audit log \
     when it ends, and every other AD CS operation is refused until then";

/// The message of [`AdcsUnavailable::NotConfigured`].
const NOT_CONFIGURED_MESSAGE: &str =
    "no AD CS authority is configured; a SuperAdmin must declare one";

/// Why no AD CS operation may start now.
#[derive(Debug)]
pub(crate) enum AdcsUnavailable {
    /// No authority is configured.
    NotConfigured,
    /// The authority is in the D15 failed state.
    Failed {
        /// The step that opened the breaker.
        step: String,
    },
    /// The authority has no password stored.
    NoPassword,
    /// The generated `krb5.conf` could not be written; the detail names
    /// a path under the data directory, so it is logged, not answered.
    Krb5Conf(String),
    /// The store failed.
    Error(ApiError),
}

impl AdcsUnavailable {
    /// The closed word an audit reason spells this refusal with.
    pub(crate) fn audit_reason(&self) -> &'static str {
        match self {
            AdcsUnavailable::NotConfigured => "not_configured",
            AdcsUnavailable::Failed { .. } => "failed_state",
            AdcsUnavailable::NoPassword => "no_password",
            AdcsUnavailable::Krb5Conf(_) => lorica_adcs::FailureStep::Krb5Conf.as_str(),
            AdcsUnavailable::Error(_) => "error",
        }
    }
}

impl From<ApiError> for AdcsUnavailable {
    fn from(err: ApiError) -> AdcsUnavailable {
        AdcsUnavailable::Error(err)
    }
}

impl From<lorica_config::ConfigError> for AdcsUnavailable {
    fn from(err: lorica_config::ConfigError) -> AdcsUnavailable {
        AdcsUnavailable::Error(err.into())
    }
}

impl From<AdcsUnavailable> for ApiError {
    fn from(unavailable: AdcsUnavailable) -> ApiError {
        match unavailable {
            AdcsUnavailable::NotConfigured => NOT_CONFIGURED.error(NOT_CONFIGURED_MESSAGE),
            AdcsUnavailable::NoPassword => NOT_CONFIGURED
                .error("the AD CS authority has no password set; a SuperAdmin must save one"),
            AdcsUnavailable::Failed { step } => FAILED_STATE.error(format!(
                "the AD CS authority is in the failed state (the KDC rejected its credential at \
                 {step}); every AD CS operation is suspended until a SuperAdmin saves a new \
                 password"
            )),
            AdcsUnavailable::Krb5Conf(detail) => {
                tracing::error!(detail = %detail, "the AD CS krb5.conf could not be written");
                KRB5_CONF.error_at(
                    lorica_adcs::FailureStep::Krb5Conf.as_str(),
                    "the generated krb5.conf could not be written; the log names the path and \
                     the cause",
                )
            }
            AdcsUnavailable::Error(err) => err,
        }
    }
}

impl From<NotRun> for ApiError {
    fn from(not_run: NotRun) -> ApiError {
        match not_run {
            NotRun::Busy => BUSY.error(BUSY_MESSAGE),
            NotRun::StillRunning => STILL_RUNNING.error(STILL_RUNNING_MESSAGE),
            NotRun::Lost(reason) => {
                ApiError::Internal(format!("the AD CS operation task failed: {reason}"))
            }
        }
    }
}

/// A follower holds no authority and runs no AD CS operation (D13),
/// break-glass window or not. The answer is the follower gate's, so a
/// follower refuses the same way whichever of the two refuses first.
pub(crate) fn refuse_on_follower(state: &AppState) -> Result<(), ApiError> {
    if let ClusterRuntime::Follower(follower) = &state.cluster {
        return Err(ApiError::Conflict(format!(
            "this node is a follower of {}: the AD CS authority is managed on the control plane",
            follower.control_plane
        )));
    }
    Ok(())
}

/// Declares [`IssuanceStep`] with its closed words and labels, so the
/// list, the words and [`IssuanceStep::ALL`] are one declaration.
macro_rules! issuance_steps {
    ($($(#[doc = $doc:literal])* $variant:ident => $word:literal, $label:literal,)*) => {
        /// A step of an issuance or a renewal that is not one of the
        /// client's ([`lorica_adcs::FailureStep`]): what the authority
        /// answered, what Lorica made of an issued certificate, and what a
        /// renewal could not build. Audit rows, `cert_issuance_failed`
        /// alerts and `error.step` carry its closed word.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum IssuanceStep {
            $($(#[doc = $doc])* $variant,)*
        }

        impl IssuanceStep {
            /// Every step, in declaration order.
            pub const ALL: &'static [IssuanceStep] = &[$(IssuanceStep::$variant,)*];

            /// The closed word of the step. Stable: it is stored and
            /// matched on outside the process.
            pub fn as_str(self) -> &'static str {
                match self {
                    $(IssuanceStep::$variant => $word,)*
                }
            }

            /// The step in words, for an operator reading a failure.
            pub fn label(self) -> &'static str {
                match self {
                    $(IssuanceStep::$variant => $label,)*
                }
            }
        }
    };
}

issuance_steps! {
    /// The authority refused the request for a lack of permission.
    FaultPermission => "fault_permission", "Authority fault: permission",
    /// The authority refused the request's template.
    FaultTemplate => "fault_template", "Authority fault: template",
    /// Any other fault of the authority.
    FaultOther => "fault_other", "Authority fault",
    /// The authority denied the request.
    Denied => "denied", "Denied by the authority",
    /// The authority holds the request for a certificate manager.
    Pending => "pending", "Pending at the authority",
    /// The issued certificate is not a server certificate (D17).
    CertificateProfile => "certificate_profile", "Issued certificate profile",
    /// The issued certificate's names are not exactly the requested ones.
    SanCoverage => "san_coverage", "Issued certificate names",
    /// The issued certificate cannot be read or served with its key.
    Certificate => "certificate", "Issued certificate",
    /// The issued certificate could not be stored.
    Store => "store", "Storing the certificate",
    /// A renewal could not read its certificate back into a request.
    Subject => "subject", "Renewal request",
    /// A renewal's names are refused by the allowlist.
    SanRefused => "san_refused", "Renewal names refused",
    /// A renewal's template is no longer allowed.
    TemplateRefused => "template_refused", "Renewal template refused",
}

impl std::fmt::Display for IssuanceStep {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;

    use super::*;

    /// The operator guide, which lists every code and every step.
    const GUIDE: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/../docs/adcs.md"));

    /// The API description, which documents every code.
    const OPENAPI: &str = include_str!(concat!(env!("CARGO_MANIFEST_DIR"), "/openapi.yaml"));

    fn every_step_word() -> Vec<&'static str> {
        lorica_adcs::FailureStep::ALL
            .iter()
            .map(|step| step.as_str())
            .chain(IssuanceStep::ALL.iter().map(|step| step.as_str()))
            .collect()
    }

    #[test]
    fn every_code_is_distinct_and_carries_a_meaning() {
        let codes: BTreeSet<&str> = ADCS_CODES.iter().map(|code| code.code).collect();
        assert_eq!(codes.len(), ADCS_CODES.len());
        for code in ADCS_CODES {
            assert!(!code.meaning.is_empty(), "{}", code.code);
            assert!(
                code.status.is_client_error() || code.status.is_server_error(),
                "{}",
                code.code
            );
        }
    }

    #[test]
    fn the_two_step_vocabularies_share_no_word() {
        let words: Vec<&str> = every_step_word();
        let distinct: BTreeSet<&str> = words.iter().copied().collect();
        assert_eq!(distinct.len(), words.len(), "{words:?}");
        let labels: BTreeSet<&str> = IssuanceStep::ALL.iter().map(|step| step.label()).collect();
        assert_eq!(labels.len(), IssuanceStep::ALL.len());
    }

    #[test]
    fn the_guide_documents_every_code_and_every_step() {
        let missing_codes: Vec<&str> = ADCS_CODES
            .iter()
            .map(|code| code.code)
            .filter(|code| !GUIDE.contains(&format!("`{code}`")))
            .collect();
        assert!(
            missing_codes.is_empty(),
            "docs/adcs.md does not name these AD CS error codes: {missing_codes:?}"
        );
        let missing_steps: Vec<&str> = every_step_word()
            .into_iter()
            .filter(|word| !GUIDE.contains(&format!("| `{word}` |")))
            .collect();
        assert!(
            missing_steps.is_empty(),
            "the troubleshooting table of docs/adcs.md has no row for these steps: \
             {missing_steps:?}"
        );
    }

    #[test]
    fn the_api_description_documents_every_code() {
        let missing: Vec<&str> = ADCS_CODES
            .iter()
            .map(|code| code.code)
            .filter(|code| !OPENAPI.contains(code))
            .collect();
        assert!(
            missing.is_empty(),
            "lorica-api/openapi.yaml does not name these AD CS error codes: {missing:?}"
        );
    }
}
