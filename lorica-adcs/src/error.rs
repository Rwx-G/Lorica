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

//! The crate's error type, and the two classifications every caller keys
//! on: the step that failed and how far the failure reaches.

use std::fmt;
use std::path::PathBuf;
use std::time::Duration;

use crate::gss::TicketFailure;

/// Declares [`FailureStep`] with its closed words, so the list of steps,
/// their words and [`FailureStep::ALL`] are one declaration.
macro_rules! failure_steps {
    ($($(#[doc = $doc:literal])* $variant:ident => $word:literal,)*) => {
        /// The step an AD CS operation failed at, as a closed word that
        /// audit rows, persisted state and alert filters match on.
        #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
        pub enum FailureStep {
            $($(#[doc = $doc])* $variant,)*
        }

        impl FailureStep {
            /// Every step, in declaration order.
            pub const ALL: &'static [FailureStep] = &[$(FailureStep::$variant,)*];

            /// The closed word of the step. Stable: it is stored and
            /// matched on outside the process.
            pub fn as_str(self) -> &'static str {
                match self {
                    $(FailureStep::$variant => $word,)*
                }
            }
        }
    };
}

failure_steps! {
    /// No KDC of the realm could be found or reached.
    KdcDiscovery => "kdc_discovery",
    /// The KDC answered and no ticket was obtained.
    TicketAcquisition => "ticket_acquisition",
    /// The SPNEGO exchange failed before mutual authentication.
    Spnego => "spnego",
    /// The endpoint did not prove it holds the service key.
    MutualAuthentication => "mutual_authentication",
    /// The channel binding could not be computed, or the endpoint's
    /// certificate changed under it.
    ChannelBinding => "channel_binding",
    /// The TLS connection to the endpoint failed.
    Tls => "tls",
    /// An HTTP leg failed below the authentication.
    Http => "http",
    /// The generated `krb5.conf` or one of its values was refused or
    /// could not be written.
    Krb5Conf => "krb5_conf",
    /// The connection parameters are unusable.
    Configuration => "configuration",
    /// The CSR could not be built.
    Csr => "csr",
    /// The SOAP envelope could not be written or the answer read.
    Soap => "soap",
    /// The issuing chain of an issued certificate could not be built.
    Chain => "chain",
    /// The operation timeout passed.
    Timeout => "timeout",
    /// A blocking task of the operation did not return.
    GssTask => "gss_task",
}

impl fmt::Display for FailureStep {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// How far a failure reaches, for a caller running several requests
/// against one authority (a renewal tick, Epic 13 D15).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FailureScope {
    /// The authority as a whole is unusable: its KDC, its credential, its
    /// endpoint's TLS or authentication, its configuration. The next
    /// request would fail the same way, so a batch stops here.
    Authority,
    /// Only this request failed (its CSR, the answer to it); the next
    /// request may succeed.
    Request,
}

/// Why an AD CS operation failed. Every variant names the step that
/// failed, so a connection test can show it as it is.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AdcsError {
    /// The GSS-API library refused the CES service name, before any
    /// network exchange.
    #[error("SPNEGO: cannot import the service name HTTP@{host}: {reason}")]
    ServiceName {
        /// The CES host the name was built from.
        host: String,
        /// What the GSS-API library reported.
        reason: String,
    },

    /// The server certificate the channel binding is computed from could
    /// not be parsed.
    #[error("channel binding: cannot parse the server certificate: {reason}")]
    ChannelBindingCertificate {
        /// What the parser reported.
        reason: String,
    },

    /// The server certificate is signed with an algorithm for which
    /// RFC 5929 4.1 defines no hash Lorica can compute.
    #[error(
        "channel binding: the server certificate is signed with {oid}, \
         which has no supported hash for tls-server-end-point (RFC 5929 4.1)"
    )]
    ChannelBindingAlgorithm {
        /// The signature algorithm OID, in dotted form.
        oid: String,
    },

    /// A connection of the operation presented a certificate other than
    /// the one the token is bound to. The handshake was refused before
    /// anything was sent on it: the token never left (Epic 13 D2).
    #[error(
        "channel binding: the endpoint presented a different certificate on a later connection \
         than the one the token is bound to; the connection was refused before the token was \
         sent (a TLS interception, or the endpoint's certificate changed mid-operation)"
    )]
    ServerCertificateChanged,

    /// A Kerberos realm failed validation; nothing was written.
    #[error("krb5.conf: invalid realm {value:?}: {reason}")]
    InvalidRealm {
        /// The value as given.
        value: String,
        /// Which rule it broke.
        reason: &'static str,
    },

    /// A KDC address failed validation; nothing was written.
    #[error("krb5.conf: invalid KDC address {value:?}: {reason}")]
    InvalidKdc {
        /// The value as given.
        value: String,
        /// Which rule it broke.
        reason: &'static str,
    },

    /// The KDC request timeout is outside its bounds.
    #[error("krb5.conf: invalid KDC timing: {reason}")]
    InvalidKdcTiming {
        /// Which bound it broke.
        reason: String,
    },

    /// The generated `krb5.conf` could not be written.
    #[error("krb5.conf: cannot write {}: {source}", path.display())]
    Krb5ConfWrite {
        /// The file or directory the failing operation targeted.
        path: PathBuf,
        /// What the operating system reported.
        #[source]
        source: std::io::Error,
    },

    /// The CSR could not be built from the given names, subject or
    /// template, or its key could not be generated.
    #[error("CSR: {reason}")]
    Csr {
        /// What was refused or what failed.
        reason: String,
    },

    /// The WS-Trust request envelope could not be written.
    #[error("SOAP envelope: {source}")]
    SoapEnvelope {
        /// What the XML writer reported.
        #[source]
        source: std::io::Error,
    },

    /// The authority's answer is not a WS-Trust response or SOAP fault
    /// this client can read.
    #[error("SOAP response: {reason}")]
    SoapResponse {
        /// What is wrong with it.
        reason: String,
    },

    /// The certificate chain of an issued response could not be built.
    #[error("certificate chain: {reason}")]
    Chain {
        /// What is wrong with it.
        reason: String,
    },

    /// The connection parameters are unusable; nothing was sent.
    #[error("configuration: {reason}")]
    InvalidParams {
        /// Which parameter and why.
        reason: String,
    },

    /// No Kerberos ticket could be obtained for the service account.
    /// The display names the step as KDC discovery when no KDC could be
    /// reached, ticket acquisition otherwise.
    #[error("{}: no ticket for {principal}: {message}", failure.label())]
    Ticket {
        /// The principal the ticket was asked for.
        principal: String,
        /// What the failure means for a caller deciding whether to try
        /// again (Epic 13 D15).
        failure: TicketFailure,
        /// The KDC's protocol error code (RFC 4120 7.5.9), when the
        /// failure carries one; [`crate::kdc_error_meaning`] says what
        /// the codes that reject the credential mean.
        kdc_error_code: Option<u32>,
        /// The GSS-API minor status as the library returned it.
        minor_status: u32,
        /// What the GSS-API library reported.
        message: String,
    },

    /// The TLS connection to the endpoint failed, or gave no server
    /// certificate to bind to.
    #[error("TLS: {reason}")]
    Tls {
        /// What failed, with the underlying error chain.
        reason: String,
    },

    /// An HTTP leg failed below the authentication: connection, timeout,
    /// an unexpected status, an unreadable body.
    #[error("HTTP {stage}: {reason}")]
    Http {
        /// Which leg: the unauthenticated probe or the authenticated
        /// request.
        stage: &'static str,
        /// What failed.
        reason: String,
    },

    /// The SPNEGO exchange failed before mutual authentication: the
    /// endpoint does not offer Negotiate, the initial token could not be
    /// built, the endpoint refused the token, or the mechanism SPNEGO
    /// settled on is not Kerberos.
    #[error("SPNEGO: {reason}")]
    Spnego {
        /// What failed.
        reason: String,
    },

    /// The endpoint did not prove it holds the service key: no response
    /// token, a token the GSS-API library rejected, or a context left
    /// incomplete or without mutual authentication (Epic 13 D2, Story
    /// 13.1 AC #5).
    #[error("SPNEGO mutual authentication: {reason}")]
    MutualAuth {
        /// What was missing or wrong.
        reason: String,
    },

    /// The operation timeout passed. Reported only once no GSS-API call
    /// of the operation is running any more (see
    /// [`crate::CesTimeouts::operation`]).
    #[error("timed out after {} s", after.as_secs())]
    Timeout {
        /// The operation timeout that elapsed.
        after: Duration,
    },

    /// A blocking task did not return (it panicked or the runtime is
    /// shutting down).
    #[error("{step}: the blocking task failed: {reason}")]
    GssTask {
        /// The step the task ran.
        step: &'static str,
        /// What the runtime reported.
        reason: String,
    },
}

impl AdcsError {
    /// The classification of a ticket failure, `None` for any other
    /// error. Story 13.2's breaker stops every attempt on
    /// [`TicketFailure::CredentialRejected`].
    pub fn ticket_failure(&self) -> Option<TicketFailure> {
        match self {
            AdcsError::Ticket { failure, .. } => Some(*failure),
            _ => None,
        }
    }

    /// The step that failed.
    pub fn step(&self) -> FailureStep {
        match self {
            AdcsError::Ticket { failure, .. } => failure.step(),
            AdcsError::ServiceName { .. } | AdcsError::Spnego { .. } => FailureStep::Spnego,
            AdcsError::MutualAuth { .. } => FailureStep::MutualAuthentication,
            AdcsError::ChannelBindingCertificate { .. }
            | AdcsError::ChannelBindingAlgorithm { .. }
            | AdcsError::ServerCertificateChanged => FailureStep::ChannelBinding,
            AdcsError::Tls { .. } => FailureStep::Tls,
            AdcsError::Http { .. } => FailureStep::Http,
            AdcsError::InvalidRealm { .. }
            | AdcsError::InvalidKdc { .. }
            | AdcsError::InvalidKdcTiming { .. }
            | AdcsError::Krb5ConfWrite { .. } => FailureStep::Krb5Conf,
            AdcsError::InvalidParams { .. } => FailureStep::Configuration,
            AdcsError::Csr { .. } => FailureStep::Csr,
            AdcsError::SoapEnvelope { .. } | AdcsError::SoapResponse { .. } => FailureStep::Soap,
            AdcsError::Chain { .. } => FailureStep::Chain,
            AdcsError::Timeout { .. } => FailureStep::Timeout,
            AdcsError::GssTask { .. } => FailureStep::GssTask,
        }
    }

    /// How far the failure reaches. Everything up to and including
    /// mutual authentication, plus the timeout and the configuration,
    /// is the authority's; what concerns one request's CSR or the answer
    /// to it is the request's. A CA denial or fault is not an error at
    /// all but an [`crate::EnrollOutcome`].
    pub fn scope(&self) -> FailureScope {
        match self.step() {
            FailureStep::Csr | FailureStep::Soap | FailureStep::Chain => FailureScope::Request,
            FailureStep::KdcDiscovery
            | FailureStep::TicketAcquisition
            | FailureStep::Spnego
            | FailureStep::MutualAuthentication
            | FailureStep::ChannelBinding
            | FailureStep::Tls
            | FailureStep::Http
            | FailureStep::Krb5Conf
            | FailureStep::Configuration
            | FailureStep::Timeout
            | FailureStep::GssTask => FailureScope::Authority,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_step_has_a_distinct_word() {
        let mut words: Vec<&str> = FailureStep::ALL
            .iter()
            .map(|step: &FailureStep| step.as_str())
            .collect();
        let count: usize = words.len();
        words.sort_unstable();
        words.dedup();
        assert_eq!(words.len(), count, "{words:?}");
        for step in FailureStep::ALL {
            assert_eq!(step.to_string(), step.as_str());
            assert!(
                step.as_str()
                    .bytes()
                    .all(|b: u8| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_'),
                "{step:?}"
            );
        }
    }

    #[test]
    fn request_scoped_failures_are_the_csr_and_the_answer() {
        let request: Vec<AdcsError> = vec![
            AdcsError::Csr {
                reason: String::new(),
            },
            AdcsError::SoapResponse {
                reason: String::new(),
            },
            AdcsError::Chain {
                reason: String::new(),
            },
        ];
        for err in &request {
            assert_eq!(err.scope(), FailureScope::Request, "{err}");
        }
        let authority: Vec<AdcsError> = vec![
            AdcsError::Ticket {
                principal: String::new(),
                failure: TicketFailure::KdcUnreachable,
                kdc_error_code: None,
                minor_status: 0,
                message: String::new(),
            },
            AdcsError::Ticket {
                principal: String::new(),
                failure: TicketFailure::CredentialRejected,
                kdc_error_code: Some(24),
                minor_status: 0,
                message: String::new(),
            },
            AdcsError::Tls {
                reason: String::new(),
            },
            AdcsError::Spnego {
                reason: String::new(),
            },
            AdcsError::MutualAuth {
                reason: String::new(),
            },
            AdcsError::ServerCertificateChanged,
            AdcsError::Timeout {
                after: Duration::from_secs(1),
            },
        ];
        for err in &authority {
            assert_eq!(err.scope(), FailureScope::Authority, "{err}");
        }
        assert_eq!(authority[0].step(), FailureStep::KdcDiscovery);
        assert_eq!(authority[1].step(), FailureStep::TicketAcquisition);
    }
}
