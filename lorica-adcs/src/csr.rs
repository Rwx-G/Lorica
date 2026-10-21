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

//! The PKCS#10 request sent to the authority (Epic 13 D4, D5): a fresh
//! key, the SANs in the extension request, a subject that is never
//! empty, and the template carried in the CSR itself.

use std::fmt;

use rcgen::string::{Ia5String, PrintableString};
use rcgen::{
    Attribute, CertificateParams, DistinguishedName, DnType, DnValue, KeyPair, RsaKeySize, SanType,
    PKCS_ECDSA_P256_SHA256, PKCS_RSA_SHA256,
};

use crate::der::{tlv, TAG_BMP_STRING, TAG_SEQUENCE, TAG_SET};
use crate::krb5conf::dns_name_problem;
use crate::AdcsError;

/// `szOID_ENROLLMENT_NAME_VALUE_PAIR` (MS-WCCE 2.2.2.7.10).
const ENROLLMENT_NAME_VALUE_PAIR_OID: &[u64] = &[1, 3, 6, 1, 4, 1, 311, 13, 2, 1];

/// The pair name the CA reads the template from (MS-WCCE 2.2.2.7.10,
/// processed per 3.2.2.6.2.1.4.1). It must be the template's common
/// name: a display name fails with 0x80094800.
const TEMPLATE_PAIR_NAME: &str = "CertificateTemplate";

/// PKCS#9 `emailAddress` (1.2.840.113549.1.9.1).
const EMAIL_ADDRESS_OID: &[u64] = &[1, 2, 840, 113549, 1, 9, 1];

/// The key generated for a request. A new key every issuance and every
/// renewal (D4).
///
/// RSA 2048 is the default because a template duplicated from *Web
/// Server* at schema version 2 uses a legacy cryptographic provider that
/// handles RSA only; ECDSA needs a version 3 or later template with a
/// key storage provider. Every request is signed with SHA-256.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[non_exhaustive]
pub enum KeyType {
    /// RSA, 2048-bit modulus. The default of D4.
    #[default]
    Rsa2048,
    /// RSA, 3072-bit modulus.
    Rsa3072,
    /// ECDSA on P-256.
    EcdsaP256,
}

/// The fixed part of the subject, held by the authority (D5). Every
/// field is optional; `CN` is never one of them, it is the first SAN.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SubjectFields {
    /// `C`, two letters (ISO 3166).
    pub country: Option<String>,
    /// `ST`.
    pub state: Option<String>,
    /// `L`.
    pub locality: Option<String>,
    /// `O`.
    pub organization: Option<String>,
    /// `OU`.
    pub organizational_unit: Option<String>,
    /// PKCS#9 `emailAddress`.
    pub email: Option<String>,
}

/// A CSR and the private key it was made for.
pub struct GeneratedCsr {
    /// The PKCS#10 request, DER.
    pub csr_der: Vec<u8>,
    /// The private key, PKCS#8 PEM. Stored encrypted by the caller; it
    /// never leaves Lorica.
    pub private_key_pem: String,
}

impl fmt::Debug for GeneratedCsr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("GeneratedCsr")
            .field("csr_der", &format_args!("{} bytes", self.csr_der.len()))
            .field("private_key_pem", &"<redacted>")
            .finish()
    }
}

fn csr_error(reason: impl Into<String>) -> AdcsError {
    AdcsError::Csr {
        reason: reason.into(),
    }
}

/// Builds the request for `sans` under `template` (its common name),
/// with a key of `key_type` and a subject of `subject` plus `CN` set to
/// the first SAN.
///
/// Refused before any key is generated: an empty SAN list, a wildcard
/// SAN (D5), a SAN that is not a DNS host name, an empty or non-BMP
/// template name, and malformed subject fields. The SANs travel only in
/// the extension request; the `san:` name-value pair, which works only
/// on an authority with `EDITF_ATTRIBUTESUBJECTALTNAME2` set (ESC6), is
/// never produced.
///
/// ```
/// use lorica_adcs::{build_csr, GeneratedCsr, KeyType, SubjectFields};
///
/// let csr: GeneratedCsr = build_csr(
///     &["web01.corp.example.org".to_owned()],
///     &SubjectFields::default(),
///     "LoricaWebServer",
///     KeyType::EcdsaP256,
/// )?;
/// assert!(!csr.csr_der.is_empty());
/// # Ok::<(), lorica_adcs::AdcsError>(())
/// ```
pub fn build_csr(
    sans: &[String],
    subject: &SubjectFields,
    template: &str,
    key_type: KeyType,
) -> Result<GeneratedCsr, AdcsError> {
    let first_san: &String = sans
        .first()
        .ok_or_else(|| csr_error("at least one subject alternative name is required"))?;
    let mut san_entries: Vec<SanType> = Vec::with_capacity(sans.len());
    for san in sans {
        if san.contains('*') {
            return Err(csr_error(format!("wildcard names are refused: {san:?}")));
        }
        if let Some(problem) = dns_name_problem(san) {
            return Err(csr_error(format!(
                "{san:?} is not a DNS host name: {problem}"
            )));
        }
        let ia5: Ia5String = Ia5String::try_from(san.as_str())
            .map_err(|err| csr_error(format!("{san:?}: {err}")))?;
        san_entries.push(SanType::DnsName(ia5));
    }
    let template_attribute: Attribute = template_attribute(template)?;
    let distinguished_name: DistinguishedName = distinguished_name(first_san, subject)?;

    let mut params: CertificateParams = CertificateParams::default();
    params.distinguished_name = distinguished_name;
    params.subject_alt_names = san_entries;

    let key: KeyPair = match key_type {
        KeyType::Rsa2048 => KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_2048),
        KeyType::Rsa3072 => KeyPair::generate_rsa_for(&PKCS_RSA_SHA256, RsaKeySize::_3072),
        KeyType::EcdsaP256 => KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256),
    }
    .map_err(|err| csr_error(format!("key generation failed: {err}")))?;
    let csr_der: Vec<u8> = params
        .serialize_request_with_attributes(&key, vec![template_attribute])
        .map_err(|err| csr_error(format!("signing the request failed: {err}")))?
        .der()
        .to_vec();
    Ok(GeneratedCsr {
        csr_der,
        private_key_pem: key.serialize_pem(),
    })
}

fn distinguished_name(
    common_name: &str,
    subject: &SubjectFields,
) -> Result<DistinguishedName, AdcsError> {
    let non_empty = |field: &'static str, value: &Option<String>| -> Result<(), AdcsError> {
        match value {
            Some(value) if value.trim().is_empty() => {
                Err(csr_error(format!("subject field {field} is empty")))
            }
            Some(value) if value.chars().any(char::is_control) => Err(csr_error(format!(
                "subject field {field} contains a control character"
            ))),
            _ => Ok(()),
        }
    };
    let mut dn: DistinguishedName = DistinguishedName::new();
    if let Some(country) = &subject.country {
        if country.len() != 2 || !country.bytes().all(|b: u8| b.is_ascii_alphabetic()) {
            return Err(csr_error(format!(
                "subject field C must be two letters, got {country:?}"
            )));
        }
        let printable: PrintableString = PrintableString::try_from(country.as_str())
            .map_err(|err| csr_error(format!("subject field C: {err}")))?;
        dn.push(DnType::CountryName, DnValue::PrintableString(printable));
    }
    let utf8_fields: [(&'static str, DnType, &Option<String>); 4] = [
        ("ST", DnType::StateOrProvinceName, &subject.state),
        ("L", DnType::LocalityName, &subject.locality),
        ("O", DnType::OrganizationName, &subject.organization),
        (
            "OU",
            DnType::OrganizationalUnitName,
            &subject.organizational_unit,
        ),
    ];
    for (label, dn_type, value) in utf8_fields {
        non_empty(label, value)?;
        if let Some(value) = value {
            dn.push(dn_type, DnValue::Utf8String(value.clone()));
        }
    }
    dn.push(
        DnType::CommonName,
        DnValue::Utf8String(common_name.to_owned()),
    );
    non_empty("emailAddress", &subject.email)?;
    if let Some(email) = &subject.email {
        let ia5: Ia5String = Ia5String::try_from(email.as_str())
            .map_err(|err| csr_error(format!("subject field emailAddress: {err}")))?;
        dn.push(
            DnType::CustomDnType(EMAIL_ADDRESS_OID.to_vec()),
            DnValue::Ia5String(ia5),
        );
    }
    Ok(dn)
}

/// The `CertificateTemplate` name-value pair as a PKCS#10 attribute.
///
/// MS-WCCE 2.2.2.7.10 defines the value as
///
/// ```text
/// EnrollmentNameValuePairs ::= SEQUENCE OF EnrollmentNameValuePair
/// EnrollmentNameValuePair ::= SEQUENCE { name BMPSTRING, value BMPSTRING }
/// ```
///
/// and the PKCS#10 `Attribute` (RFC 2986 4.1) carries its values in a
/// `SET OF`. The collection is that set, one `EnrollmentNameValuePair`
/// per value, which is how Windows' own enrollment clients encode the
/// attribute (the CryptoAPI structure for this OID is a single pair):
///
/// ```text
/// SET { SEQUENCE { BMPString "CertificateTemplate", BMPString <cn> } }
/// ```
fn template_attribute(template: &str) -> Result<Attribute, AdcsError> {
    if template.trim().is_empty() {
        return Err(csr_error("the template name is empty"));
    }
    if template.chars().any(char::is_control) {
        return Err(csr_error("the template name contains a control character"));
    }
    let pair: Vec<u8> = tlv(
        TAG_SEQUENCE,
        &[bmp_string(TEMPLATE_PAIR_NAME)?, bmp_string(template)?].concat(),
    );
    Ok(Attribute {
        oid: ENROLLMENT_NAME_VALUE_PAIR_OID,
        values: tlv(TAG_SET, &pair),
    })
}

/// A DER `BMPString`: UCS-2, big-endian (X.690 8.23.8). Characters
/// outside the Basic Multilingual Plane have no UCS-2 form and are
/// refused rather than encoded as surrogate pairs.
fn bmp_string(value: &str) -> Result<Vec<u8>, AdcsError> {
    if value.chars().any(|c: char| u32::from(c) > 0xFFFF) {
        return Err(csr_error(format!(
            "{value:?} has characters outside the Basic Multilingual Plane"
        )));
    }
    let ucs2: Vec<u8> = value
        .encode_utf16()
        .flat_map(|unit: u16| unit.to_be_bytes())
        .collect();
    Ok(tlv(TAG_BMP_STRING, &ucs2))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::der_split;
    use x509_parser::certification_request::X509CertificationRequest;
    use x509_parser::der_parser::asn1_rs::{Any, FromDer, Oid};
    use x509_parser::extensions::{GeneralName, ParsedExtension};
    use x509_parser::public_key::PublicKey;

    const EXTENSION_REQUEST_OID: &str = "1.2.840.113549.1.9.14";
    const TEMPLATE_OID: &str = "1.3.6.1.4.1.311.13.2.1";

    fn sans(names: &[&str]) -> Vec<String> {
        names.iter().map(|name: &&str| (*name).to_owned()).collect()
    }

    fn full_subject() -> SubjectFields {
        SubjectFields {
            country: Some("FR".to_owned()),
            state: Some("Ile-de-France".to_owned()),
            locality: Some("Paris".to_owned()),
            organization: Some("Example Corp".to_owned()),
            organizational_unit: Some("IT".to_owned()),
            email: Some("pki@corp.example.org".to_owned()),
        }
    }

    /// Every attribute of the CSR as (dotted OID, raw `SET OF` values),
    /// read from the DER rather than from x509-parser, which keeps only
    /// the header of attributes it does not know.
    fn attributes(csr_der: &[u8]) -> Vec<(String, Vec<u8>)> {
        let request: &[u8] = der_split(csr_der)[0];
        let attributes_tlv: &[u8] = der_split(request)
            .into_iter()
            .find(|tlv: &&[u8]| tlv[0] == 0xA0)
            .expect("attributes [0]");
        der_split(attributes_tlv)
            .into_iter()
            .map(|attribute: &[u8]| {
                let parts: Vec<&[u8]> = der_split(attribute);
                let (_, oid): (&[u8], Oid<'_>) = Oid::from_der(parts[0]).expect("oid");
                (oid.to_id_string(), parts[1].to_vec())
            })
            .collect()
    }

    fn decode_bmp(tlv: &[u8]) -> String {
        let (_, any): (&[u8], Any<'_>) = Any::from_der(tlv).expect("bmp");
        assert_eq!(any.header.tag().0, u32::from(TAG_BMP_STRING));
        let units: Vec<u16> = any
            .data
            .chunks(2)
            .map(|pair: &[u8]| u16::from_be_bytes([pair[0], pair[1]]))
            .collect();
        String::from_utf16(&units).expect("utf-16")
    }

    #[test]
    fn template_attribute_has_the_exact_bytes_for_a_known_name() {
        let csr: GeneratedCsr = build_csr(
            &sans(&["web01.corp.example.org"]),
            &SubjectFields::default(),
            "WebServer",
            KeyType::EcdsaP256,
        )
        .expect("csr");
        let template: Vec<u8> = attributes(&csr.csr_der)
            .into_iter()
            .find(|(oid, _)| oid == TEMPLATE_OID)
            .expect("template attribute")
            .1;
        // SET { SEQUENCE { BMPString "CertificateTemplate",
        //                  BMPString "WebServer" } }, written out by hand.
        let expected: Vec<u8> = [
            &[0x31, 0x3E, 0x30, 0x3C, 0x1E, 0x26][..],
            &[
                0x00, 0x43, 0x00, 0x65, 0x00, 0x72, 0x00, 0x74, 0x00, 0x69, 0x00, 0x66, 0x00, 0x69,
                0x00, 0x63, 0x00, 0x61, 0x00, 0x74, 0x00, 0x65, 0x00, 0x54, 0x00, 0x65, 0x00, 0x6D,
                0x00, 0x70, 0x00, 0x6C, 0x00, 0x61, 0x00, 0x74, 0x00, 0x65,
            ],
            &[0x1E, 0x12],
            &[
                0x00, 0x57, 0x00, 0x65, 0x00, 0x62, 0x00, 0x53, 0x00, 0x65, 0x00, 0x72, 0x00, 0x76,
                0x00, 0x65, 0x00, 0x72,
            ],
        ]
        .concat();
        assert_eq!(template, expected);
    }

    #[test]
    fn the_only_attributes_are_the_extension_request_and_the_template() {
        let csr: GeneratedCsr = build_csr(
            &sans(&["web01.corp.example.org", "www.corp.example.org"]),
            &full_subject(),
            "LoricaWebServer",
            KeyType::EcdsaP256,
        )
        .expect("csr");
        let found: Vec<(String, Vec<u8>)> = attributes(&csr.csr_der);
        let oids: Vec<&str> = found.iter().map(|(oid, _)| oid.as_str()).collect();
        assert_eq!(oids, vec![EXTENSION_REQUEST_OID, TEMPLATE_OID]);
        // No `san:` pair, whatever its case: every name-value pair in the
        // request is the template one.
        let template_values: &[u8] = &found[1].1;
        for pair in der_split(template_values) {
            let fields: Vec<&[u8]> = der_split(pair);
            let name: String = decode_bmp(fields[0]);
            assert!(!name.eq_ignore_ascii_case("san"));
            assert_eq!(name, TEMPLATE_PAIR_NAME);
            assert_eq!(decode_bmp(fields[1]), "LoricaWebServer");
        }
    }

    #[test]
    fn subject_is_never_empty_and_cn_is_the_first_san() {
        for subject in [SubjectFields::default(), full_subject()] {
            let csr: GeneratedCsr = build_csr(
                &sans(&["web01.corp.example.org", "www.corp.example.org"]),
                &subject,
                "LoricaWebServer",
                KeyType::EcdsaP256,
            )
            .expect("csr");
            let (_, request): (&[u8], X509CertificationRequest<'_>) =
                X509CertificationRequest::from_der(&csr.csr_der).expect("parse csr");
            let subject_name = &request.certification_request_info.subject;
            assert!(subject_name.iter_rdn().next().is_some(), "empty subject");
            let cns: Vec<&str> = subject_name
                .iter_common_name()
                .map(|cn| cn.as_str().expect("utf8 cn"))
                .collect();
            assert_eq!(cns, vec!["web01.corp.example.org"]);
        }
    }

    #[test]
    fn fixed_subject_fields_are_carried() {
        let csr: GeneratedCsr = build_csr(
            &sans(&["web01.corp.example.org"]),
            &full_subject(),
            "LoricaWebServer",
            KeyType::EcdsaP256,
        )
        .expect("csr");
        let (_, request): (&[u8], X509CertificationRequest<'_>) =
            X509CertificationRequest::from_der(&csr.csr_der).expect("parse csr");
        let rendered: String = request.certification_request_info.subject.to_string();
        for part in [
            "C=FR",
            "ST=Ile-de-France",
            "L=Paris",
            "O=Example Corp",
            "OU=IT",
            "CN=web01.corp.example.org",
            "pki@corp.example.org",
        ] {
            assert!(rendered.contains(part), "{part} missing from {rendered}");
        }
    }

    #[test]
    fn sans_are_in_the_extension_request() {
        let names: Vec<String> = sans(&["web01.corp.example.org", "www.corp.example.org"]);
        let csr: GeneratedCsr = build_csr(
            &names,
            &SubjectFields::default(),
            "LoricaWebServer",
            KeyType::EcdsaP256,
        )
        .expect("csr");
        let (_, request): (&[u8], X509CertificationRequest<'_>) =
            X509CertificationRequest::from_der(&csr.csr_der).expect("parse csr");
        let mut found: Vec<String> = Vec::new();
        for extension in request.requested_extensions().expect("extension request") {
            if let ParsedExtension::SubjectAlternativeName(san) = extension {
                for name in &san.general_names {
                    if let GeneralName::DNSName(dns) = name {
                        found.push((*dns).to_owned());
                    }
                }
            }
        }
        assert_eq!(found, names);
    }

    #[test]
    fn private_key_matches_the_request_and_is_not_debug_printed() {
        let csr: GeneratedCsr = build_csr(
            &sans(&["web01.corp.example.org"]),
            &SubjectFields::default(),
            "LoricaWebServer",
            KeyType::default(),
        )
        .expect("csr");
        let key: KeyPair = KeyPair::from_pem(&csr.private_key_pem).expect("pem key");
        let (_, request): (&[u8], X509CertificationRequest<'_>) =
            X509CertificationRequest::from_der(&csr.csr_der).expect("parse csr");
        assert_eq!(
            request.certification_request_info.subject_pki.raw,
            rcgen::PublicKeyData::subject_public_key_info(&key).as_slice()
        );
        assert!(!format!("{csr:?}").contains("PRIVATE KEY"));
    }

    #[test]
    fn every_request_gets_a_new_key() {
        let build = || {
            build_csr(
                &sans(&["web01.corp.example.org"]),
                &SubjectFields::default(),
                "LoricaWebServer",
                KeyType::EcdsaP256,
            )
            .expect("csr")
            .private_key_pem
        };
        assert_ne!(build(), build());
    }

    #[test]
    fn refused_inputs() {
        let subject: SubjectFields = SubjectFields::default();
        let refused = |names: &[&str], subject: &SubjectFields, template: &str| {
            matches!(
                build_csr(&sans(names), subject, template, KeyType::EcdsaP256),
                Err(AdcsError::Csr { .. })
            )
        };
        assert!(refused(&[], &subject, "WebServer"));
        assert!(refused(&["*.corp.example.org"], &subject, "WebServer"));
        assert!(refused(
            &["web01.corp.example.org", "*.corp.example.org"],
            &subject,
            "WebServer"
        ));
        assert!(refused(&["web01 corp"], &subject, "WebServer"));
        assert!(refused(
            &["web01.corp.example.org\n"],
            &subject,
            "WebServer"
        ));
        assert!(refused(&["web01.corp.example.org"], &subject, ""));
        assert!(refused(&["web01.corp.example.org"], &subject, "  "));
        assert!(refused(
            &["web01.corp.example.org"],
            &subject,
            "Web\u{1F600}"
        ));
        for bad_country in ["FRA", "F", "1A"] {
            let subject: SubjectFields = SubjectFields {
                country: Some(bad_country.to_owned()),
                ..SubjectFields::default()
            };
            assert!(refused(&["web01.corp.example.org"], &subject, "WebServer"));
        }
        let empty_ou: SubjectFields = SubjectFields {
            organizational_unit: Some(String::new()),
            ..SubjectFields::default()
        };
        assert!(refused(&["web01.corp.example.org"], &empty_ou, "WebServer"));
        let non_ascii_email: SubjectFields = SubjectFields {
            email: Some("pk\u{e9}@corp.example.org".to_owned()),
            ..SubjectFields::default()
        };
        assert!(refused(
            &["web01.corp.example.org"],
            &non_ascii_email,
            "WebServer"
        ));
    }

    #[test]
    fn rsa_2048_is_the_default_key_type() {
        assert_eq!(KeyType::default(), KeyType::Rsa2048);
    }

    #[test]
    fn each_key_type_yields_its_algorithm_and_size() {
        // (key type, SPKI algorithm, key size in bits, signature algorithm)
        let cases: [(KeyType, &str, usize, &str); 3] = [
            (
                KeyType::Rsa2048,
                "1.2.840.113549.1.1.1",
                2048,
                "1.2.840.113549.1.1.11",
            ),
            (
                KeyType::Rsa3072,
                "1.2.840.113549.1.1.1",
                3072,
                "1.2.840.113549.1.1.11",
            ),
            (
                KeyType::EcdsaP256,
                "1.2.840.10045.2.1",
                256,
                "1.2.840.10045.4.3.2",
            ),
        ];
        for (key_type, spki_oid, bits, signature_oid) in cases {
            let csr: GeneratedCsr = build_csr(
                &sans(&["web01.corp.example.org"]),
                &SubjectFields::default(),
                "LoricaWebServer",
                key_type,
            )
            .expect("csr");
            let (_, request): (&[u8], X509CertificationRequest<'_>) =
                X509CertificationRequest::from_der(&csr.csr_der).expect("parse csr");
            let spki = &request.certification_request_info.subject_pki;
            assert_eq!(
                spki.algorithm.algorithm.to_id_string(),
                spki_oid,
                "{key_type:?}"
            );
            let parsed: PublicKey<'_> = spki.parsed().expect("public key");
            let size: usize = match &parsed {
                PublicKey::RSA(rsa) => rsa.key_size(),
                PublicKey::EC(ec) => ec.key_size(),
                other => panic!("{key_type:?}: unexpected key {other:?}"),
            };
            assert_eq!(size, bits, "{key_type:?}");
            if key_type == KeyType::EcdsaP256 {
                let curve: String = spki
                    .algorithm
                    .parameters
                    .as_ref()
                    .expect("curve parameter")
                    .as_oid()
                    .expect("curve oid")
                    .to_id_string();
                assert_eq!(curve, "1.2.840.10045.3.1.7");
            }
            assert_eq!(
                request.signature_algorithm.algorithm.to_id_string(),
                signature_oid,
                "{key_type:?}"
            );
            KeyPair::from_pem(&csr.private_key_pem).expect("the private key parses back");
        }
    }

    #[test]
    fn bmp_string_is_ucs2_big_endian() {
        assert_eq!(
            bmp_string("A\u{e9}").expect("bmp"),
            vec![0x1E, 0x04, 0x00, 0x41, 0x00, 0xE9]
        );
    }
}
