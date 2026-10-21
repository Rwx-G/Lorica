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

#![deny(clippy::all)]
#![deny(unsafe_code)]
#![warn(missing_docs)]

//! The AD CS enrollment client of Lorica (Epic 13): it turns a CSR into
//! an issued certificate through an authority's Certificate Enrollment
//! Web Service (CES), which speaks WS-Trust (MS-WSTEP) over SOAP 1.2 and
//! HTTPS and authenticates with Kerberos SPNEGO bound to the TLS channel.
//!
//! The crate holds the protocol client and nothing else (Epic 13 decision
//! D8): ticket acquisition, the channel binding, the SPNEGO exchange, the
//! WS-Trust envelope, response and fault parsing, chain extraction, CSR
//! construction and the `krb5.conf` renderer. It depends on no
//! first-party crate and knows nothing about the store, routes or the
//! dashboard; when to issue, renew and store is `lorica-api`'s business.
//!
//! The calls the rest of Lorica makes are [`enroll`], which turns a CSR
//! from [`build_csr`] into an [`EnrollOutcome`], and [`test_connection`],
//! which authenticates without requesting anything. Both read the
//! Kerberos configuration from the file `KRB5_CONFIG` names, which the
//! `lorica` binary sets to [`krb5_config_path`] at startup and Story
//! 13.2 writes with [`Krb5Config::write_to`].

mod binding;
mod chain;
mod client;
mod csr;
mod der;
mod error;
mod gss;
mod krb5conf;
mod secret;
#[cfg(test)]
mod test_support;
mod wstep;

pub use binding::channel_binding;
pub use chain::chain_from_cmc;
pub use client::{enroll, test_connection, CesParams, CesTimeouts, EnrollOutcome};
pub use csr::{build_csr, GeneratedCsr, KeyType, SubjectFields};
pub use error::AdcsError;
pub use gss::TicketFailure;
pub use krb5conf::{krb5_config_path, write_atomically, KdcAddress, KdcTiming, Krb5Config, Realm};
pub use secret::Secret;
pub use wstep::request::{build_request, new_message_id, SOAP_CONTENT_TYPE};
pub use wstep::response::{parse_response, EnrollmentResponse, FaultKind};

use libgssapi::name::Name;
use libgssapi::oid::GSS_NT_HOSTBASED_SERVICE;

/// The GSS-API name of the CES web service on `host`, `HTTP@<host>` as a
/// host-based service name: the Kerberos target a client asks a ticket
/// for, which the library maps to the principal `HTTP/<host>`.
///
/// Importing the name is local to the library: it contacts no KDC and
/// resolves nothing.
pub fn service_name(host: &str) -> Result<Name, AdcsError> {
    let service: String = format!("HTTP@{host}");
    Name::new(service.as_bytes(), Some(GSS_NT_HOSTBASED_SERVICE)).map_err(
        |source: libgssapi::error::Error| AdcsError::ServiceName {
            host: host.to_owned(),
            source,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use libgssapi::oid::GSS_MECH_SPNEGO;

    // Both calls go through the system GSS-API library, so this test
    // failing to link is the build telling us libgssapi-krb5 is missing.
    #[test]
    fn service_name_is_imported_by_the_system_library() {
        let name: Name = service_name("ces.corp.example.org").expect("import HTTP@ host name");
        assert!(name.to_string().contains("ces.corp.example.org"));
        // 1.3.6.1.5.5.2, RFC 4178.
        assert_eq!(&*GSS_MECH_SPNEGO, b"\x2b\x06\x01\x05\x05\x02");
    }
}
