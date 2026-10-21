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

use std::borrow::Cow;

use libgssapi::context::{ClientCtx, CtxFlags, SecurityContext as _};
use libgssapi::credential::{Cred, CredUsage};
use libgssapi::name::Name;
use libgssapi::oid::{OidSet, GSS_MECH_KRB5, GSS_MECH_SPNEGO, GSS_NT_KRB5_PRINCIPAL};
use x509_parser::der_parser::asn1_rs::Oid;

use crate::error::FailureStep;
use crate::secret::Secret;
use crate::AdcsError;

/// What a failed ticket acquisition means for whoever decides whether to
/// try again (Epic 13 D15).
///
/// The classification fails closed: a failure is
/// [`TicketFailure::KdcUnreachable`] only when it is positively
/// recognised as such, and everything else, an unknown or localised
/// message included, is a [`TicketFailure::CredentialRejected`], which
/// stops every further attempt against the account. A KDC that cannot be
/// reached costs the account nothing; a rejection that went unrecognised
/// would cost it one failed pre-authentication per attempt until it
/// locks.
///
/// Recognition reads the GSS-API minor status, which MIT's mechanism
/// glue passes through unchanged for the Kerberos mechanism when no other
/// mechanism produced the same value, and falls back to MIT's message
/// text when the number is not one it knows, which is the usual case:
/// the credential is acquired through SPNEGO, whose glue renumbers the
/// Kerberos status. libgssapi exposes no other way to the raw code.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TicketFailure {
    /// The KDC refused the credential, or the failure was not recognised
    /// as an unreachable KDC. Trying again can only lock the account;
    /// Story 13.2 stops every attempt. [`crate::kdc_error_meaning`] says
    /// what the codes the KDC gives for a refused credential mean.
    CredentialRejected,
    /// No KDC of the realm could be found or reached: the realm has no
    /// SRV records, a KDC name does not resolve, or no KDC answered.
    KdcUnreachable,
}

impl TicketFailure {
    /// The step a failure of this class is reported under.
    pub fn step(self) -> FailureStep {
        match self {
            TicketFailure::KdcUnreachable => FailureStep::KdcDiscovery,
            TicketFailure::CredentialRejected => FailureStep::TicketAcquisition,
        }
    }

    /// The step in words, as the error displays it.
    pub(crate) fn label(self) -> &'static str {
        match self {
            TicketFailure::KdcUnreachable => "KDC discovery",
            TicketFailure::CredentialRejected => "ticket acquisition",
        }
    }
}

/// `ERROR_TABLE_BASE_krb5` of MIT's `krb5.h`. The first 128 codes of the
/// table are the protocol error codes of RFC 4120 7.5.9 at the same
/// offset.
const KRB5_ERROR_TABLE_BASE: i64 = -1_765_328_384;
const KRB5_PROTOCOL_CODES: u32 = 128;

/// A KDC refusal the operator can act on: its RFC 4120 code, the
/// lower-case fragment of MIT's message for it (the text is what is left
/// when the mechanism glue renumbered the minor status, which is always
/// the case for a credential acquired through SPNEGO, so the code is
/// recovered from it), and what it means.
struct KnownRejection {
    code: u32,
    fragment: &'static str,
    meaning: &'static str,
}

const CREDENTIAL_REJECTED: [KnownRejection; 4] = [
    KnownRejection {
        code: 18, // KDC_ERR_CLIENT_REVOKED
        fragment: "credentials have been revoked",
        meaning: "the account is disabled or locked out",
    },
    KnownRejection {
        code: 23, // KDC_ERR_KEY_EXPIRED
        fragment: "password has expired",
        meaning: "the password has expired",
    },
    KnownRejection {
        code: 24, // KDC_ERR_PREAUTH_FAILED
        fragment: "preauthentication failed",
        meaning: "the password is wrong",
    },
    KnownRejection {
        // KRB_AP_ERR_BAD_INTEGRITY: how a wrong password shows when the
        // account does not require pre-authentication.
        code: 31,
        fragment: "decrypt integrity check failed",
        meaning: "the password is wrong (the account does not require pre-authentication)",
    },
];

/// What the KDC protocol error `code` (RFC 4120 7.5.9) means for the
/// service account, for the codes that reject its credential; `None`
/// for any other code.
///
/// ```
/// assert_eq!(lorica_adcs::kdc_error_meaning(24), Some("the password is wrong"));
/// assert_eq!(lorica_adcs::kdc_error_meaning(6), None);
/// ```
pub fn kdc_error_meaning(code: u32) -> Option<&'static str> {
    CREDENTIAL_REJECTED
        .iter()
        .find(|known: &&KnownRejection| known.code == code)
        .map(|known: &KnownRejection| known.meaning)
}

/// The MIT codes that mean no KDC could be reached, each with the
/// lower-case fragment of MIT's message for it, for a minor status the
/// mechanism glue renumbered.
const KDC_UNREACHABLE: [(i64, &str); 3] = [
    // KRB5_REALM_UNKNOWN
    (-1_765_328_230, "cannot find kdc"),
    // KRB5_KDC_UNREACH
    (-1_765_328_228, "cannot contact any kdc"),
    // KRB5_REALM_CANT_RESOLVE
    (-1_765_328_164, "cannot resolve network address for kdc"),
];

/// The krb5 code a GSS-API minor status carries. GSS-API reports the
/// code, a negative `long`, as an unsigned 32-bit value: read it back as
/// signed.
fn as_krb5_code(minor_status: u32) -> i64 {
    i64::from(i32::from_ne_bytes(minor_status.to_ne_bytes()))
}

/// The RFC 4120 error code a GSS-API minor status carries, when it is
/// one of MIT's protocol error codes.
pub(crate) fn kdc_error_code(minor_status: u32) -> Option<u32> {
    let offset: i64 = as_krb5_code(minor_status) - KRB5_ERROR_TABLE_BASE;
    u32::try_from(offset)
        .ok()
        .filter(|code: &u32| (1..KRB5_PROTOCOL_CODES).contains(code))
}

/// Classifies a failed acquisition from its minor status and message,
/// numbers first, then MIT's text, then fail closed.
pub(crate) fn classify_ticket_failure(
    minor_status: u32,
    message: &str,
) -> (TicketFailure, Option<u32>) {
    let krb5_code: i64 = as_krb5_code(minor_status);
    if KDC_UNREACHABLE
        .iter()
        .any(|(code, _): &(i64, &str)| *code == krb5_code)
    {
        return (TicketFailure::KdcUnreachable, None);
    }
    if let Some(code) = kdc_error_code(minor_status) {
        return (TicketFailure::CredentialRejected, Some(code));
    }
    let lower: String = message.to_ascii_lowercase();
    if let Some(known) = CREDENTIAL_REJECTED
        .iter()
        .find(|known: &&KnownRejection| lower.contains(known.fragment))
    {
        return (TicketFailure::CredentialRejected, Some(known.code));
    }
    if KDC_UNREACHABLE
        .iter()
        .any(|(_, fragment): &(i64, &str)| lower.contains(fragment))
    {
        return (TicketFailure::KdcUnreachable, None);
    }
    (TicketFailure::CredentialRejected, None)
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

/// The OIDs MIT recognises as the Kerberos mechanism besides
/// [`GSS_MECH_KRB5`]: Microsoft's historical one (1.2.840.48018.1.2.2),
/// which Windows still answers SPNEGO with, and the pre-RFC 1964 one
/// (1.3.5.1.5.2). DER contents octets.
const LEGACY_KERBEROS_MECHANISMS: [&[u8]; 2] = [
    b"\x2a\x86\x48\x82\xf7\x12\x01\x02\x02",
    b"\x2b\x05\x01\x05\x02",
];

/// What an established context negotiated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Negotiated {
    /// The mechanism SPNEGO settled on, DER contents octets.
    pub(crate) mechanism: Vec<u8>,
    /// Whether the returned flags carry mutual authentication.
    pub(crate) mutual: bool,
}

impl Negotiated {
    /// Whether the mechanism is Kerberos (Epic 13 D2: no NTLM, nor any
    /// other mechanism a host may have registered for SPNEGO to offer).
    pub(crate) fn is_kerberos(&self) -> bool {
        let mechanism: &[u8] = &self.mechanism;
        mechanism == &*GSS_MECH_KRB5 || LEGACY_KERBEROS_MECHANISMS.contains(&mechanism)
    }

    /// The mechanism in dotted form, for an error.
    pub(crate) fn mechanism_name(&self) -> String {
        Oid::new(Cow::Borrowed(&self.mechanism)).to_id_string()
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
    /// An acquired credential. Each context gets a clone, so one
    /// credential serves every request of a session (Epic 13 D15: one
    /// ticket per session) and is released when the last clone drops.
    type Credential: Clone + Send + 'static;
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

    /// Whether the context is established.
    fn is_complete(&self) -> bool;

    /// The mechanism and flags of an established context.
    fn negotiated(&self) -> Result<Negotiated, GssFailure>;
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
        // SPNEGO alone: MIT's SPNEGO acquires the krb5 element itself, and
        // naming krb5 beside it makes the mechanism glue acquire a second
        // time, one more AS exchange per operation and, with a wrong
        // password, two failed pre-authentications against the account
        // lockout instead of one (Epic 13 D15). Measured against the
        // harness KDC on MIT 1.20 and 1.21, and pinned by
        // `tests/harness.rs`. Restricting what SPNEGO negotiates up front
        // would take `gss_set_neg_mechs`, which libgssapi 0.11 does not
        // expose; the mechanism is checked once the context is
        // established instead (see `Negotiated::is_kerberos`).
        let mut mechanisms: OidSet = OidSet::new();
        mechanisms
            .add(GSS_MECH_SPNEGO)
            .map_err(|err: libgssapi::error::Error| AdcsError::Spnego {
                reason: format!("cannot build the mechanism set: {err}"),
            })?;
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

    fn negotiated(&self) -> Result<Negotiated, GssFailure> {
        let failure = |err: libgssapi::error::Error| GssFailure {
            message: err.to_string(),
        };
        // On an established SPNEGO context MIT reports the mechanism of
        // the context SPNEGO wraps, not SPNEGO's own OID.
        let mechanism: Vec<u8> = self.0.mechanism().map_err(failure)?.to_vec();
        let flags: CtxFlags = self.0.flags().map_err(failure)?;
        Ok(Negotiated {
            mechanism,
            mutual: flags.contains(CtxFlags::GSS_C_MUTUAL_FLAG),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The unsigned form GSS-API gives a krb5 code.
    fn minor(code: i64) -> u32 {
        u32::from_ne_bytes(i32::try_from(code).expect("krb5 code").to_ne_bytes())
    }

    /// A minor status the mechanism glue renumbered: no number we know.
    const RENUMBERED: u32 = 100_001;

    #[test]
    fn credential_rejections_are_classified_from_the_minor_status() {
        for known in &CREDENTIAL_REJECTED {
            let status: u32 = minor(KRB5_ERROR_TABLE_BASE + i64::from(known.code));
            assert_eq!(kdc_error_code(status), Some(known.code));
            assert_eq!(
                classify_ticket_failure(status, "renumbered message"),
                (TicketFailure::CredentialRejected, Some(known.code))
            );
            assert_eq!(kdc_error_meaning(known.code), Some(known.meaning));
        }
    }

    #[test]
    fn unreachable_kdcs_are_classified_from_the_minor_status() {
        for (code, _) in KDC_UNREACHABLE {
            assert_eq!(
                classify_ticket_failure(minor(code), "renumbered message"),
                (TicketFailure::KdcUnreachable, None)
            );
        }
    }

    #[test]
    fn a_renumbered_status_falls_back_to_the_message() {
        // The minor status and message a wrong password produced through
        // SPNEGO against the harness KDC (MIT 1.20).
        assert_eq!(
            classify_ticket_failure(
                RENUMBERED,
                "No credentials were supplied, or the credentials were unavailable or \
                 inaccessible (Preauthentication failed)"
            ),
            (TicketFailure::CredentialRejected, Some(24))
        );
        for known in &CREDENTIAL_REJECTED {
            let message: String = format!(
                "Unspecified GSS failure ({})",
                known.fragment.to_uppercase()
            );
            assert_eq!(
                classify_ticket_failure(RENUMBERED, &message),
                (TicketFailure::CredentialRejected, Some(known.code)),
                "{message}"
            );
        }
        for (_, fragment) in KDC_UNREACHABLE {
            let message: String = format!("Unspecified GSS failure ({fragment} for realm 'X')");
            assert_eq!(
                classify_ticket_failure(RENUMBERED, &message),
                (TicketFailure::KdcUnreachable, None),
                "{message}"
            );
        }
    }

    // Pen M2: a rejection whose text is not recognised (a localised MIT
    // catalogue, a reworded release) must still stop every attempt.
    #[test]
    fn an_unrecognised_failure_fails_closed_as_a_rejection() {
        for message in [
            "Échec de la pré-authentification",
            "Vorauthentifizierung fehlgeschlagen",
            "Unspecified GSS failure.  Minor code may provide more information",
            "",
        ] {
            assert_eq!(
                classify_ticket_failure(RENUMBERED, message),
                (TicketFailure::CredentialRejected, None),
                "{message}"
            );
        }
        // Any KDC protocol code, not only the four with a meaning:
        // KDC_ERR_C_PRINCIPAL_UNKNOWN (6), KRB_AP_ERR_SKEW (37).
        for code in [6, 37] {
            let status: u32 = minor(KRB5_ERROR_TABLE_BASE + code);
            assert_eq!(
                classify_ticket_failure(status, "anything"),
                (TicketFailure::CredentialRejected, u32::try_from(code).ok())
            );
        }
    }

    // A rejection fragment wins over an unreachable one in the same
    // message: the error that can cost the account is the one kept.
    #[test]
    fn a_rejection_wins_over_unreachable_text() {
        assert_eq!(
            classify_ticket_failure(
                RENUMBERED,
                "Cannot contact any KDC; Preauthentication failed"
            ),
            (TicketFailure::CredentialRejected, Some(24))
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
        assert_eq!(err.step(), FailureStep::TicketAcquisition);
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
            minor(KDC_UNREACHABLE[1].0),
            "Cannot contact any KDC".to_owned(),
        );
        assert_eq!(unreachable.step(), FailureStep::KdcDiscovery);
        assert!(
            unreachable.to_string().starts_with("KDC discovery: "),
            "{unreachable}"
        );
    }

    #[test]
    fn kerberos_is_recognised_under_each_of_its_oids() {
        let negotiated = |mechanism: &[u8]| Negotiated {
            mechanism: mechanism.to_vec(),
            mutual: true,
        };
        assert!(negotiated(&GSS_MECH_KRB5).is_kerberos());
        assert_eq!(
            negotiated(&GSS_MECH_KRB5).mechanism_name(),
            "1.2.840.113554.1.2.2"
        );
        let legacy: Vec<String> = LEGACY_KERBEROS_MECHANISMS
            .iter()
            .map(|oid: &&[u8]| {
                assert!(negotiated(oid).is_kerberos());
                negotiated(oid).mechanism_name()
            })
            .collect();
        assert_eq!(legacy, ["1.2.840.48018.1.2.2", "1.3.5.1.5.2"]);
        // NTLMSSP (1.3.6.1.4.1.311.2.2.10), SPNEGO itself and IAKERB are
        // not Kerberos for this check.
        let others: [&[u8]; 3] = [
            b"\x2b\x06\x01\x04\x01\x82\x37\x02\x02\x0a",
            &GSS_MECH_SPNEGO,
            b"\x2b\x06\x01\x05\x02\x05",
        ];
        for other in others {
            assert!(!negotiated(other).is_kerberos(), "{other:?}");
        }
    }
}
