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

//! What a write of the AD CS authority may carry (Story 13.2, Epic 13
//! D3, D5, D11, D17): every field checked, with the rules `lorica_adcs`
//! applies before it connects, so a value the client would refuse at
//! the first operation is refused when it is saved. The subject rule is
//! the CSR builder's, shared with issuance.

use lorica_adcs::{AdcsError, CesEndpoint, KdcAddress, Principal, Realm, Secret};
use lorica_config::models::{
    validate_template_name, AdcsKeyType, AdcsSubjectDefaults, AllowedSuffix,
    ADCS_ALLOWED_TEMPLATES_MAX,
};
use serde::Deserialize;

use crate::error::ApiError;

/// The service account password of a write, accepted and never shown:
/// its `Debug` is redacted and it has no `Serialize`.
pub struct WritePassword(Secret);

impl<'de> Deserialize<'de> for WritePassword {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        String::deserialize(deserializer).map(|text: String| WritePassword(Secret::new(text)))
    }
}

impl std::fmt::Debug for WritePassword {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("WritePassword(<redacted>)")
    }
}

/// Body of `PUT /api/v1/adcs/authority`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AdcsAuthorityRequest {
    /// The CES endpoint, `https://` with a DNS host name.
    pub endpoint: String,
    /// The Kerberos realm, `^[A-Z0-9][A-Z0-9.-]*$`.
    pub realm: String,
    /// Explicit KDCs as `host[:port]`, at most [`MAX_KDCS`]; empty means
    /// DNS SRV discovery.
    #[serde(default)]
    pub kdcs: Vec<String>,
    /// The service account, `user` or `user@REALM`.
    pub principal: String,
    /// The service account password. Required on creation and with any
    /// change of `endpoint`, `realm`, `kdcs`, `principal` or
    /// `endpoint_ca_pem`; optional otherwise, where it replaces the
    /// stored one. Never returned.
    #[serde(default)]
    pub password: Option<WritePassword>,
    /// PEM certificates trusted, alone, for the endpoint's TLS
    /// certificate.
    #[serde(default)]
    pub endpoint_ca_pem: Option<String>,
    /// The issuing CA certificate, PEM. Absent (or `null`) keeps the
    /// stored one, which an issuance may have learned since the caller
    /// read the authority; blank clears it.
    #[serde(default)]
    pub issuing_ca_pem: Option<String>,
    /// The template's common name.
    pub default_template: String,
    /// The other template common names an issuance may request (D17);
    /// the default template is always permitted.
    #[serde(default)]
    pub allowed_templates: Vec<String>,
    /// The key type of a new certificate.
    #[serde(default)]
    pub default_key_type: AdcsKeyType,
    /// The fixed part of every subject.
    #[serde(default)]
    pub subject: AdcsSubjectDefaults,
    /// DNS suffixes Lorica may request names under; at least one.
    pub allowed_suffixes: Vec<String>,
    /// The auto-renew setting a newly issued certificate starts with.
    pub auto_renew_default: bool,
}

/// The most explicit KDCs an authority may list. MIT tries them in
/// turn, each silent one costing its own retry schedule while the
/// operation holds the single-flight guard, so the list is bounded.
pub const MAX_KDCS: usize = 10;

/// The configuration part of a request once every field is valid.
pub(super) struct ValidatedRequest {
    pub(super) endpoint: String,
    pub(super) realm: String,
    pub(super) kdcs: Vec<String>,
    pub(super) principal: String,
    pub(super) endpoint_ca_pem: Option<String>,
    /// `None` keeps the stored certificate; `Some(None)` clears it.
    pub(super) issuing_ca_pem: Option<Option<String>>,
    pub(super) default_template: String,
    pub(super) allowed_templates: Vec<String>,
    pub(super) default_key_type: AdcsKeyType,
    pub(super) subject: AdcsSubjectDefaults,
    pub(super) allowed_suffixes: Vec<AllowedSuffix>,
    pub(super) auto_renew_default: bool,
}

fn refuse(reason: String) -> ApiError {
    ApiError::Unprocessable(reason)
}

/// A PEM bundle of at least one certificate, every block a certificate
/// x509-parser reads. `None` and blank stay unset.
fn validate_pem_bundle(field: &str, raw: Option<String>) -> Result<Option<String>, ApiError> {
    let Some(text) = raw.map(|text: String| text.trim().to_string()) else {
        return Ok(None);
    };
    if text.is_empty() {
        return Ok(None);
    }
    let blocks: Vec<pem::Pem> =
        pem::parse_many(&text).map_err(|err| refuse(format!("{field}: not PEM ({err})")))?;
    if blocks.is_empty() {
        return Err(refuse(format!("{field}: no PEM certificate found")));
    }
    for block in &blocks {
        if block.tag() != "CERTIFICATE" {
            return Err(refuse(format!(
                "{field}: every PEM block must be a CERTIFICATE, found {}",
                block.tag()
            )));
        }
        x509_parser::parse_x509_certificate(block.contents())
            .map_err(|err| refuse(format!("{field}: unreadable certificate ({err})")))?;
    }
    Ok(Some(text))
}

/// Trimmed, blank as unset, the country uppercased, and refused by the
/// rule the CSR builder applies ([`lorica_adcs::SubjectFields::check`]),
/// so a subject the authority's defaults or a request carry is refused
/// when it is sent rather than at the first CSR built from it.
pub(crate) fn validate_subject(
    subject: AdcsSubjectDefaults,
) -> Result<AdcsSubjectDefaults, ApiError> {
    let clean = |value: Option<String>| -> Option<String> {
        value
            .map(|text: String| text.trim().to_string())
            .filter(|text: &String| !text.is_empty())
    };
    let AdcsSubjectDefaults {
        country,
        state,
        locality,
        organization,
        organizational_unit,
        email,
    } = subject;
    let cleaned: AdcsSubjectDefaults = AdcsSubjectDefaults {
        country: clean(country).map(|code: String| code.to_ascii_uppercase()),
        state: clean(state),
        locality: clean(locality),
        organization: clean(organization),
        organizational_unit: clean(organizational_unit),
        email: clean(email),
    };
    subject_fields(&cleaned)
        .check()
        .map_err(|err: AdcsError| refuse(format!("subject: {err}")))?;
    Ok(cleaned)
}

/// The CSR builder's view of `subject`. Destructured without `..`, so a
/// field added to [`AdcsSubjectDefaults`] does not compile until it is
/// carried here.
pub(crate) fn subject_fields(subject: &AdcsSubjectDefaults) -> lorica_adcs::SubjectFields {
    let AdcsSubjectDefaults {
        country,
        state,
        locality,
        organization,
        organizational_unit,
        email,
    } = subject;
    lorica_adcs::SubjectFields {
        country: country.clone(),
        state: state.clone(),
        locality: locality.clone(),
        organization: organization.clone(),
        organizational_unit: organizational_unit.clone(),
        email: email.clone(),
    }
}

/// The allowed template list as stored: each name trimmed and checked,
/// the default first, no name twice (ignoring ASCII case, as the
/// authority does).
fn allowed_template_list(
    default_template: &str,
    requested: &[String],
) -> Result<Vec<String>, ApiError> {
    let mut list: Vec<String> = vec![default_template.to_string()];
    for raw in requested {
        let name: &str = raw.trim();
        validate_template_name("allowed_templates", name)?;
        if !list
            .iter()
            .any(|kept: &String| kept.eq_ignore_ascii_case(name))
        {
            list.push(name.to_string());
        }
    }
    if list.len() > ADCS_ALLOWED_TEMPLATES_MAX {
        return Err(refuse(format!(
            "allowed_templates: at most {ADCS_ALLOWED_TEMPLATES_MAX} templates, the default \
             included"
        )));
    }
    Ok(list)
}

impl AdcsAuthorityRequest {
    /// Validate every field, splitting the password off. The endpoint,
    /// realm, KDC and principal rules are `lorica_adcs`'s own, the ones
    /// the client applies before it connects, so a value refused at the
    /// first operation is refused here instead.
    pub(super) fn validate(self) -> Result<(ValidatedRequest, Option<Secret>), ApiError> {
        let endpoint: &str = self.endpoint.trim();
        CesEndpoint::new(endpoint).map_err(|err: AdcsError| refuse(format!("endpoint: {err}")))?;
        let realm: Realm =
            Realm::new(self.realm.trim()).map_err(|err: AdcsError| refuse(err.to_string()))?;
        if self.kdcs.len() > MAX_KDCS {
            return Err(refuse(format!(
                "kdcs: at most {MAX_KDCS} KDCs, {} given",
                self.kdcs.len()
            )));
        }
        let kdcs: Vec<String> = self
            .kdcs
            .iter()
            .map(|kdc: &String| {
                KdcAddress::new(kdc.trim())
                    .map(|address: KdcAddress| address.to_string())
                    .map_err(|err: AdcsError| refuse(err.to_string()))
            })
            .collect::<Result<Vec<String>, ApiError>>()?;
        let principal: &str = self.principal.trim();
        Principal::new(principal, &realm)
            .map_err(|err: AdcsError| refuse(format!("principal: {err}")))?;
        let default_template: String = self.default_template.trim().to_string();
        validate_template_name("default_template", &default_template)?;
        let allowed_templates: Vec<String> =
            allowed_template_list(&default_template, &self.allowed_templates)?;
        if self.allowed_suffixes.is_empty() {
            return Err(refuse(
                "allowed_suffixes: at least one DNS suffix is required".to_string(),
            ));
        }
        let allowed_suffixes: Vec<AllowedSuffix> = self
            .allowed_suffixes
            .iter()
            .map(|suffix: &String| AllowedSuffix::new(suffix.trim()))
            .collect::<Result<Vec<AllowedSuffix>, lorica_config::ConfigError>>()?;
        let validated: ValidatedRequest = ValidatedRequest {
            endpoint: endpoint.to_string(),
            realm: realm.as_str().to_string(),
            kdcs,
            principal: principal.to_string(),
            endpoint_ca_pem: validate_pem_bundle("endpoint_ca_pem", self.endpoint_ca_pem)?,
            issuing_ca_pem: self
                .issuing_ca_pem
                .map(|raw: String| validate_pem_bundle("issuing_ca_pem", Some(raw)))
                .transpose()?,
            default_template,
            allowed_templates,
            default_key_type: self.default_key_type,
            subject: validate_subject(self.subject)?,
            allowed_suffixes,
            auto_renew_default: self.auto_renew_default,
        };
        Ok((
            validated,
            self.password.map(|password: WritePassword| password.0),
        ))
    }
}
