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

//! The GSS-API side of the exchange behind a trait, so the HTTP, SOAP
//! and binding logic are tested without a KDC (Story 13.1 AC #11), and
//! the classification of ticket failures Story 13.2's breaker keys on.
//!
//! Every call here is synchronous FFI that may perform DNS and KDC
//! network I/O; the caller runs it on `spawn_blocking`.

use libgssapi::context::{ClientCtx, CtxFlags, SecurityContext as _};
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::name::Name;
use libgssapi::oid::{OidSet, GSS_MECH_KRB5, GSS_MECH_SPNEGO, GSS_NT_KRB5_PRINCIPAL};

use crate::secret::Secret;
use crate::AdcsError;

/// What a failed ticket acquisition means for whoever decides whether to
/// try again (Epic 13 D15).
///
/// The classification reads the GSS-API minor status, which MIT's
/// mechanism glue passes through unchanged for the Kerberos mechanism
/// when no other mechanism produced the same value, and falls back to
/// MIT's message text when the number is not one it knows. Anything not
/// recognised either way is [`TicketFailure::Other`]: an unknown failure
/// is never promoted to a credential rejection, and never hides one
/// either, since the message is kept in the error.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TicketFailure {
    /// The KDC refused the credential: wrong password
    /// (`KDC_ERR_PREAUTH_FAILED`, 24, or a reply that does not decrypt,
    /// `KRB_AP_ERR_BAD_INTEGRITY`, 31, which is how a wrong password
    /// shows when the account does not require pre-authentication),
    /// a disabled or locked account (`KDC_ERR_CLIENT_REVOKED`, 18) or an
    /// expired password (`KDC_ERR_KEY_EXPIRED`, 23). Trying again can
    /// only lock the account; Story 13.2 stops every attempt.
    CredentialRejected,
    /// No KDC of the realm could be found or reached: the realm has no
    /// SRV records, a KDC name does not resolve, or no KDC answered.
    KdcUnreachable,
    /// Anything else: an unknown principal, clock skew, a library error.
    Other,
}

impl TicketFailure {
    /// The step name an error of this class is displayed under.
    pub fn step(self) -> &'static str {
        match self {
            TicketFailure::KdcUnreachable => "KDC discovery",
            TicketFailure::CredentialRejected | TicketFailure::Other => "ticket acquisition",
        }
    }
}

/// `ERROR_TABLE_BASE_krb5` of MIT's `krb5.h`. The first 128 codes of the
/// table are the protocol error codes of RFC 4120 7.5.9 at the same
/// offset.
const KRB5_ERROR_TABLE_BASE: i64 = -1_765_328_384;
const KRB5_PROTOCOL_CODES: u32 = 128;

const KDC_ERR_CLIENT_REVOKED: u32 = 18;
const KDC_ERR_KEY_EXPIRED: u32 = 23;
const KDC_ERR_PREAUTH_FAILED: u32 = 24;
const KRB_AP_ERR_BAD_INTEGRITY: u32 = 31;
const CREDENTIAL_REJECTED_CODES: [u32; 4] = [
    KDC_ERR_CLIENT_REVOKED,
    KDC_ERR_KEY_EXPIRED,
    KDC_ERR_PREAUTH_FAILED,
    KRB_AP_ERR_BAD_INTEGRITY,
];

/// `KRB5_REALM_UNKNOWN` ("Cannot find KDC for requested realm"),
/// `KRB5_KDC_UNREACH` ("Cannot contact any KDC for requested realm") and
/// `KRB5_REALM_CANT_RESOLVE` ("Cannot resolve network address for KDC in
/// requested realm"), from MIT's `krb5.h`.
const KDC_UNREACHABLE_CODES: [i64; 3] = [-1_765_328_230, -1_765_328_228, -1_765_328_164];

/// Lower-case fragments of MIT's messages for the codes above, for a
/// minor status the mechanism glue renumbered.
const CREDENTIAL_REJECTED_TEXT: [&str; 4] = [
    "preauthentication failed",
    "credentials have been revoked",
    "password has expired",
    "decrypt integrity check failed",
];
const KDC_UNREACHABLE_TEXT: [&str; 3] = [
    "cannot find kdc",
    "cannot contact any kdc",
    "cannot resolve network address for kdc",
];

/// The RFC 4120 error code a GSS-API minor status carries, when it is
/// one of MIT's protocol error codes.
pub(crate) fn kdc_error_code(minor_status: u32) -> Option<u32> {
    // GSS-API reports the krb5 code, a negative `long`, as an unsigned
    // 32-bit value: read it back as signed before taking the offset.
    let signed: i64 = i64::from(i32::from_ne_bytes(minor_status.to_ne_bytes()));
    let offset: i64 = signed - KRB5_ERROR_TABLE_BASE;
    u32::try_from(offset)
        .ok()
        .filter(|code: &u32| (1..KRB5_PROTOCOL_CODES).contains(code))
}

/// Classifies a failed acquisition from its minor status and message.
pub(crate) fn classify_ticket_failure(
    minor_status: u32,
    message: &str,
) -> (TicketFailure, Option<u32>) {
    let kdc_code: Option<u32> = kdc_error_code(minor_status);
    if kdc_code.is_some_and(|code: u32| CREDENTIAL_REJECTED_CODES.contains(&code)) {
        return (TicketFailure::CredentialRejected, kdc_code);
    }
    let signed: i64 = i64::from(i32::from_ne_bytes(minor_status.to_ne_bytes()));
    if KDC_UNREACHABLE_CODES.contains(&signed) {
        return (TicketFailure::KdcUnreachable, kdc_code);
    }
    let lower: String = message.to_ascii_lowercase();
    if CREDENTIAL_REJECTED_TEXT
        .iter()
        .any(|fragment: &&str| lower.contains(fragment))
    {
        return (TicketFailure::CredentialRejected, kdc_code);
    }
    if KDC_UNREACHABLE_TEXT
        .iter()
        .any(|fragment: &&str| lower.contains(fragment))
    {
        return (TicketFailure::KdcUnreachable, kdc_code);
    }
    (TicketFailure::Other, kdc_code)
}

/// The [`AdcsError::Ticket`] for a failed acquisition.
pub(crate) fn ticket_error(principal: &str, minor_status: u32, message: String) -> AdcsError {
    let (failure, kdc_error_code): (TicketFailure, Option<u32>) =
        classify_ticket_failure(minor_status, &message);
    AdcsError::Ticket {
        principal: principal.to_owned(),
        failure,
        kdc_error_code,
        minor_status,
        message,
    }
}

/// A failed context step, before the caller turns it into the error of
/// the step it was running.
#[derive(Debug)]
pub(crate) struct GssFailure {
    pub(crate) message: String,
}

/// Credential acquisition and client context creation.
pub(crate) trait GssBackend: Send + Sync + 'static {
    /// An acquired credential, consumed by [`Self::client_context`].
    type Credential: Send + 'static;
    /// A client security context.
    type Context: GssContext;

    /// Obtains a ticket for `principal` (`user@REALM`) with `password`.
    fn acquire_credential(
        &self,
        principal: &str,
        password: &Secret,
    ) -> Result<Self::Credential, AdcsError>;

    /// A SPNEGO client context with `credential` for `HTTP@<host>`,
    /// requesting mutual authentication.
    fn client_context(
        &self,
        credential: Self::Credential,
        host: &str,
    ) -> Result<Self::Context, AdcsError>;
}

/// One client security context. It moves between blocking tasks, never
/// shared, which is why `Send` is all it needs.
pub(crate) trait GssContext: Send + 'static {
    /// Feeds `input_token` (none on the first call) with the channel
    /// binding as `application_data`, and returns the token to send, if
    /// any.
    fn step(
        &mut self,
        input_token: Option<&[u8]>,
        channel_binding: &[u8],
    ) -> Result<Option<Vec<u8>>, GssFailure>;

    /// Whether the context is established, mutual authentication
    /// included.
    fn is_complete(&self) -> bool;
}

/// The system GSS-API library through `libgssapi`.
pub(crate) struct LibGssapi;

/// A [`ClientCtx`] behind [`GssContext`].
pub(crate) struct LibGssapiContext(ClientCtx);

impl GssBackend for LibGssapi {
    type Credential = Cred;
    type Context = LibGssapiContext;

    fn acquire_credential(&self, principal: &str, password: &Secret) -> Result<Cred, AdcsError> {
        let name: Name = Name::new(principal.as_bytes(), Some(GSS_NT_KRB5_PRINCIPAL)).map_err(
            |err: libgssapi::error::Error| AdcsError::InvalidParams {
                reason: format!("the principal {principal:?} is not a Kerberos name: {err}"),
            },
        )?;
        let mut mechanisms: OidSet = OidSet::new();
        for mechanism in [GSS_MECH_SPNEGO, GSS_MECH_KRB5] {
            mechanisms
                .add(mechanism)
                .map_err(|err: libgssapi::error::Error| {
                    ticket_error(principal, err.minor, err.to_string())
                })?;
        }
        // MIT acquires into a fresh `MEMORY:` cache of its own (Epic 13
        // D3): no default ccache is read or written.
        password
            .expose(|text: &str| {
                Cred::acquire_with_password(
                    Some(&name),
                    text,
                    None,
                    CredUsage::Initiate,
                    Some(&mechanisms),
                )
            })
            .map_err(|err: libgssapi::error::Error| {
                ticket_error(principal, err.minor, err.to_string())
            })
    }

    fn client_context(&self, credential: Cred, host: &str) -> Result<LibGssapiContext, AdcsError> {
        let target: Name = crate::service_name(host)?;
        Ok(LibGssapiContext(ClientCtx::new(
            Some(credential),
            target,
            CtxFlags::GSS_C_MUTUAL_FLAG,
            Some(GSS_MECH_SPNEGO),
        )))
    }
}

impl GssContext for LibGssapiContext {
    fn step(
        &mut self,
        input_token: Option<&[u8]>,
        channel_binding: &[u8],
    ) -> Result<Option<Vec<u8>>, GssFailure> {
        self.0
            .step(input_token, Some(channel_binding))
            .map(|token| token.map(|buffer| buffer.to_vec()))
            .map_err(|err: libgssapi::error::Error| GssFailure {
                message: err.to_string(),
            })
    }

    fn is_complete(&self) -> bool {
        self.0.is_complete()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The unsigned form GSS-API gives a krb5 code.
    fn minor(code: i64) -> u32 {
        u32::from_ne_bytes(i32::try_from(code).expect("krb5 code").to_ne_bytes())
    }

    #[test]
    fn credential_rejections_are_classified_from_the_minor_status() {
        for code in CREDENTIAL_REJECTED_CODES {
            let status: u32 = minor(KRB5_ERROR_TABLE_BASE + i64::from(code));
            assert_eq!(kdc_error_code(status), Some(code));
            assert_eq!(
                classify_ticket_failure(status, "renumbered message"),
                (TicketFailure::CredentialRejected, Some(code))
            );
        }
    }

    #[test]
    fn unreachable_kdcs_are_classified_from_the_minor_status() {
        for code in KDC_UNREACHABLE_CODES {
            assert_eq!(
                classify_ticket_failure(minor(code), "renumbered message"),
                (TicketFailure::KdcUnreachable, None)
            );
        }
    }

    // A minor status the mechanism glue renumbered carries no number we
    // know; MIT's text still names the cause.
    #[test]
    fn a_renumbered_status_falls_back_to_the_message() {
        let renumbered: u32 = 100_000;
        assert_eq!(
            classify_ticket_failure(
                renumbered,
                "Unspecified GSS failure.  Minor code may provide more information (Preauthentication failed)"
            ),
            (TicketFailure::CredentialRejected, None)
        );
        assert_eq!(
            classify_ticket_failure(
                renumbered,
                "Unspecified GSS failure (Cannot contact any KDC for realm 'CORP.EXAMPLE.ORG')"
            ),
            (TicketFailure::KdcUnreachable, None)
        );
    }

    #[test]
    fn anything_else_is_other_and_keeps_its_kdc_code() {
        // KDC_ERR_C_PRINCIPAL_UNKNOWN, 6.
        let status: u32 = minor(KRB5_ERROR_TABLE_BASE + 6);
        assert_eq!(
            classify_ticket_failure(status, "Client not found in Kerberos database"),
            (TicketFailure::Other, Some(6))
        );
        assert_eq!(
            classify_ticket_failure(0, "an unexpected failure"),
            (TicketFailure::Other, None)
        );
    }

    #[test]
    fn the_error_names_the_step_and_carries_the_code() {
        let err: AdcsError = ticket_error(
            "svc-lorica@CORP.EXAMPLE.ORG",
            minor(KRB5_ERROR_TABLE_BASE + 24),
            "Preauthentication failed".to_owned(),
        );
        assert_eq!(
            err.ticket_failure(),
            Some(TicketFailure::CredentialRejected)
        );
        assert!(matches!(
            err,
            AdcsError::Ticket {
                kdc_error_code: Some(24),
                ..
            }
        ));
        assert!(err.to_string().starts_with("ticket acquisition: "), "{err}");
        let unreachable: AdcsError = ticket_error(
            "svc-lorica@CORP.EXAMPLE.ORG",
            minor(KDC_UNREACHABLE_CODES[1]),
            "Cannot contact any KDC".to_owned(),
        );
        assert!(
            unreachable.to_string().starts_with("KDC discovery: "),
            "{unreachable}"
        );
    }
}
