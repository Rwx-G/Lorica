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

//! What Lorica reads from an AD CS leaf certificate: whether it is a
//! server certificate with exactly the requested names (D17), the
//! template it names, and the issuing CA certificate it verifies under
//! (D12). Issuance reads an issued leaf, adoption a stored one.

use std::collections::BTreeSet;

use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::asn1_rs::{Any, FromDer, Oid, Tag};
use x509_parser::extensions::GeneralName;

/// Version 2 and later templates (MS-WCCE 2.2.2.7.7.2): a SEQUENCE
/// whose first element is the template OID.
const TEMPLATE_V2_EXTENSION_OID: &str = "1.3.6.1.4.1.311.21.7";

/// Version 1 templates (MS-WCCE 2.2.2.7.7.1): the template name as a
/// string, BMPString in practice.
const TEMPLATE_V1_EXTENSION_OID: &str = "1.3.6.1.4.1.311.20.2";

/// `names` as a refusal quotes them.
pub(super) fn quoted(names: &[String]) -> String {
    names
        .iter()
        .map(|name: &String| format!("{name:?}"))
        .collect::<Vec<String>>()
        .join(", ")
}

/// What the leaf says, read once.
pub(super) struct LeafFacts {
    /// Its `dNSName` entries, lowercased.
    dns_names: Vec<String>,
    /// Every other subject alternative name, described.
    other_names: Vec<String>,
    /// Whether its extended key usage includes Server Authentication.
    server_auth: bool,
    /// Whether its extended key usage includes Any Purpose.
    any_purpose: bool,
    /// Whether `basicConstraints` makes it a CA.
    is_ca: bool,
    /// The template it names (see [`template_oid_of`]).
    pub(super) template_oid: Option<String>,
}

impl LeafFacts {
    /// Why the leaf is not a server certificate (D17), or `None`.
    pub(super) fn profile_problem(&self) -> Option<&'static str> {
        if self.is_ca {
            Some("the authority issued a CA certificate (basicConstraints cA true)")
        } else if !self.server_auth {
            Some(
                "the authority issued a certificate without the Server Authentication extended \
                 key usage",
            )
        } else if self.any_purpose {
            Some("the authority issued a certificate with the Any Purpose extended key usage")
        } else {
            None
        }
    }

    /// Why the leaf's names are not exactly `requested`, or `None`.
    /// Both sides are lowercase DNS names here, so the comparison is
    /// case-insensitive.
    pub(super) fn names_problem(&self, requested: &[String]) -> Option<String> {
        let issued: BTreeSet<&str> = self.dns_names.iter().map(String::as_str).collect();
        let asked: BTreeSet<&str> = requested.iter().map(String::as_str).collect();
        let missing: Vec<String> = asked
            .difference(&issued)
            .map(|name: &&str| (*name).to_string())
            .collect();
        let mut extra: Vec<String> = issued
            .difference(&asked)
            .map(|name: &&str| (*name).to_string())
            .collect();
        extra.extend(self.other_names.iter().cloned());
        if missing.is_empty() && extra.is_empty() {
            return None;
        }
        let mut parts: Vec<String> = Vec::new();
        if !missing.is_empty() {
            parts.push(format!("does not cover {}", quoted(&missing)));
        }
        if !extra.is_empty() {
            parts.push(format!("names what was not requested: {}", quoted(&extra)));
        }
        Some(format!(
            "the authority issued a certificate that {}",
            parts.join(" and ")
        ))
    }
}

/// A subject alternative name that is not a DNS name, in words.
fn describe_other_name(name: &GeneralName<'_>) -> String {
    match name {
        GeneralName::RFC822Name(address) => format!("email {address}"),
        GeneralName::URI(uri) => format!("URI {uri}"),
        GeneralName::IPAddress(_) => "an IP address".to_string(),
        GeneralName::OtherName(oid, _) => format!("other name {}", oid.to_id_string()),
        GeneralName::RegisteredID(oid) => format!("registered ID {}", oid.to_id_string()),
        _ => "a name that is not a DNS name".to_string(),
    }
}

/// The leaf's facts. An extension present twice, which x509-parser
/// refuses to choose between, fails the read: what the certificate may
/// do must not be guessed.
pub(super) fn leaf_facts(leaf_der: &[u8]) -> Result<LeafFacts, String> {
    let (_, leaf): (&[u8], X509Certificate<'_>) = x509_parser::parse_x509_certificate(leaf_der)
        .map_err(|err| format!("the issued certificate does not parse: {err}"))?;
    let mut dns_names: Vec<String> = Vec::new();
    let mut other_names: Vec<String> = Vec::new();
    let san = leaf.subject_alternative_name().map_err(|err| {
        format!("the issued certificate's subject alternative names cannot be read: {err}")
    })?;
    if let Some(san) = san {
        for name in &san.value.general_names {
            match name {
                GeneralName::DNSName(dns) => dns_names.push(dns.to_ascii_lowercase()),
                other => other_names.push(describe_other_name(other)),
            }
        }
    }
    let eku = leaf.extended_key_usage().map_err(|err| {
        format!("the issued certificate's extended key usage cannot be read: {err}")
    })?;
    let is_ca: bool = leaf
        .basic_constraints()
        .map_err(|err| format!("the issued certificate's basic constraints cannot be read: {err}"))?
        .is_some_and(|constraints| constraints.value.ca);
    Ok(LeafFacts {
        dns_names,
        other_names,
        server_auth: eku.as_ref().is_some_and(|usage| usage.value.server_auth),
        any_purpose: eku.as_ref().is_some_and(|usage| usage.value.any),
        is_ca,
        template_oid: template_oid_of(&leaf),
    })
}

/// The first certificate of the issued chain, as PEM, when the leaf's
/// signature verifies under its key: the only issuing CA the authority
/// may learn from an issuance (D12). Names and key identifiers are
/// copied at will, so they alone prove nothing.
pub(super) fn verified_issuing_ca(leaf_der: &[u8], chain_der: &[Vec<u8>]) -> Option<String> {
    let issuer_der: &Vec<u8> = chain_der.first()?;
    let (_, leaf) = x509_parser::parse_x509_certificate(leaf_der).ok()?;
    let (_, issuer) = x509_parser::parse_x509_certificate(issuer_der).ok()?;
    lorica_adcs::issued_by(&leaf, &issuer).then(|| pem_certificate(issuer_der))
}

/// The template an issued certificate names: the OID of extension
/// 1.3.6.1.4.1.311.21.7 (version 2 and later templates), else the name
/// in 1.3.6.1.4.1.311.20.2 (version 1), else `None`.
pub(crate) fn template_oid_of(leaf: &X509Certificate<'_>) -> Option<String> {
    let extension_value = |oid: &str| -> Option<&[u8]> {
        leaf.extensions()
            .iter()
            .find(|extension| extension.oid.to_id_string() == oid)
            .map(|extension| extension.value)
    };
    extension_value(TEMPLATE_V2_EXTENSION_OID)
        .and_then(template_v2_oid)
        .or_else(|| extension_value(TEMPLATE_V1_EXTENSION_OID).and_then(template_v1_name))
}

/// `CertificateTemplate ::= SEQUENCE { templateID OBJECT IDENTIFIER,
/// templateMajorVersion INTEGER, templateMinorVersion INTEGER OPTIONAL }`.
fn template_v2_oid(value: &[u8]) -> Option<String> {
    let (_, sequence): (&[u8], Any<'_>) = Any::from_der(value).ok()?;
    if sequence.header.tag() != Tag::Sequence {
        return None;
    }
    let (_, oid): (&[u8], Oid<'_>) = Oid::from_der(sequence.data).ok()?;
    Some(oid.to_id_string())
}

/// The version 1 template name, a BMPString in practice and a
/// UTF8String from some issuers.
fn template_v1_name(value: &[u8]) -> Option<String> {
    let (_, string): (&[u8], Any<'_>) = Any::from_der(value).ok()?;
    let name: String = match string.header.tag() {
        Tag::BmpString => {
            if string.data.len() % 2 != 0 {
                return None;
            }
            let units: Vec<u16> = string
                .data
                .chunks_exact(2)
                .map(|pair: &[u8]| u16::from_be_bytes([pair[0], pair[1]]))
                .collect();
            String::from_utf16(&units).ok()?
        }
        Tag::Utf8String => std::str::from_utf8(string.data).ok()?.to_string(),
        _ => return None,
    };
    (!name.is_empty()).then_some(name)
}

/// `der` as one PEM `CERTIFICATE` block, LF line endings.
pub(super) fn pem_certificate(der: &[u8]) -> String {
    pem::encode_config(
        &pem::Pem::new("CERTIFICATE", der),
        pem::EncodeConfig::new().set_line_ending(pem::LineEnding::LF),
    )
}
