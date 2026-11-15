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

//! Client certificate verification on a terminating stream (Story 12.4
//! D-h), on the route's `MtlsConfig` model.
//!
//! One verifier per stream, built from the stream's own bundle: a stream
//! owns its listening socket (Story 12.1 AC #7), so its handshake never
//! verifies against the union of several bundles, the defect 1.10.3 fixed
//! for routes. With `required` false a client without a certificate
//! passes as anonymous, but a certificate that does not chain still fails
//! the handshake: nothing else on the socket could have admitted it.
//!
//! The organization allowlist runs after the handshake, through
//! `organizations_admitted`, the predicate HTTP routes share, over the
//! `O=` values `get_organizations_serial_bytes` reads for them too.

use std::sync::Arc;

use lorica_config::models::{organizations_admitted, MtlsConfig};
use lorica_core::utils::tls::get_organizations_serial_bytes;
use lorica_tls::http_client::{crypto_provider, pem_roots};
use lorica_tls::{CertificateDer, ClientCertVerifier, WebPkiClientVerifier};

use crate::handler::ClientCertificateOutcome;

/// The verifier of a stream whose client authentication is `config`.
///
/// # Errors
///
/// A sentence when the bundle does not load in full (`pem_roots` is
/// strict) or rustls refuses it; the stream's terminating connections
/// are then refused, never verified against less than the operator
/// wrote.
pub fn verifier(config: &MtlsConfig) -> Result<Arc<dyn ClientCertVerifier>, String> {
    let roots = pem_roots(config.ca_cert_pem.as_bytes())
        .map_err(|e| format!("the client CA bundle does not load: {e}"))?;
    let builder = WebPkiClientVerifier::builder_with_provider(Arc::new(roots), crypto_provider());
    let builder = if config.required {
        builder
    } else {
        builder.allow_unauthenticated()
    };
    builder
        .build()
        .map_err(|e| format!("the client verifier cannot be built: {e}"))
}

/// What a completed handshake's client certificate (`presented`, leaf
/// first, as rustls verified it) means for a stream authenticating
/// clients with `config`: `None` refuses the connection
/// `client_certificate` before any backend is chosen.
///
/// The allowlist applies only to a client that presented a certificate,
/// as on routes; an empty allowlist admits every verified certificate.
pub fn admit(
    config: &MtlsConfig,
    presented: Option<&[CertificateDer<'_>]>,
) -> Option<ClientCertificateOutcome> {
    let Some(leaf) = presented.and_then(<[CertificateDer<'_>]>::first) else {
        return Some(ClientCertificateOutcome::Absent);
    };
    if config.allowed_organizations.is_empty() {
        return Some(ClientCertificateOutcome::Verified);
    }
    let (organizations, _serial) = get_organizations_serial_bytes(leaf.as_ref()).ok()?;
    organizations_admitted(&config.allowed_organizations, &organizations)
        .then_some(ClientCertificateOutcome::Verified)
}

#[cfg(test)]
mod tests {
    use super::*;
    use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};

    fn leaf_with_organization(organization: &str) -> CertificateDer<'static> {
        let key = KeyPair::generate().unwrap();
        let mut params = CertificateParams::new(vec!["client".into()]).unwrap();
        let mut dn = DistinguishedName::new();
        dn.push(DnType::OrganizationName, organization);
        params.distinguished_name = dn;
        params.self_signed(&key).unwrap().der().clone()
    }

    fn config(ca: &str, required: bool, allowed: &[&str]) -> MtlsConfig {
        MtlsConfig {
            ca_cert_pem: ca.to_string(),
            required,
            allowed_organizations: allowed.iter().map(|o| o.to_string()).collect(),
        }
    }

    #[test]
    fn the_allowlist_reads_the_leaf_organizations_and_spares_an_absent_certificate() {
        let leaf = [leaf_with_organization("Acme")];
        let open = config("", true, &[]);
        let acme = config("", true, &["Acme"]);
        let other = config("", true, &["Other"]);
        assert_eq!(
            admit(&open, Some(&leaf)),
            Some(ClientCertificateOutcome::Verified)
        );
        assert_eq!(
            admit(&acme, Some(&leaf)),
            Some(ClientCertificateOutcome::Verified)
        );
        assert_eq!(admit(&other, Some(&leaf)), None);
        assert_eq!(admit(&other, None), Some(ClientCertificateOutcome::Absent));
        assert_eq!(
            admit(&other, Some(&[])),
            Some(ClientCertificateOutcome::Absent)
        );
    }

    #[test]
    fn a_bundle_that_does_not_load_builds_no_verifier() {
        assert!(verifier(&config("not a bundle", true, &[])).is_err());
        let key = KeyPair::generate().unwrap();
        let ca = CertificateParams::new(vec!["ca".into()])
            .unwrap()
            .self_signed(&key)
            .unwrap();
        assert!(verifier(&config(&ca.pem(), true, &[])).is_ok());
        assert!(verifier(&config(&ca.pem(), false, &[])).is_ok());
    }
}
