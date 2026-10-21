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

//! The crate's error type.

use std::path::PathBuf;

/// Why an AD CS operation failed. Every variant names the step that
/// failed, so a connection test can show it as it is.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum AdcsError {
    /// The GSS-API library refused the CES service name, before any
    /// network exchange.
    #[error("SPNEGO: cannot import the service name HTTP@{host}: {source}")]
    ServiceName {
        /// The CES host the name was built from.
        host: String,
        /// What the GSS-API library reported.
        #[source]
        source: libgssapi::error::Error,
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

    /// The KDC timeout or retry count is outside its bounds.
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
}
