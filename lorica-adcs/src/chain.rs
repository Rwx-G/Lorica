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

//! The issuing chain of an issued certificate, read from the CMC Full
//! PKI Response that CES returns beside it (MS-WSTEP 3.1.4.1.3.2,
//! Epic 13 D7).
//!
//! Only the `certificates` set of the CMS `SignedData` is read. Its
//! order means nothing and it includes the root, so the path is rebuilt
//! from the leaf. The CMC signature, the encapsulated `PKIResponse` and
//! the signer infos are ignored: the chain Lorica keeps is verified as a
//! certificate path where it is used, not here.

use x509_parser::certificate::X509Certificate;
use x509_parser::der_parser::asn1_rs::{Any, Class, FromDer, Oid, Tag};
use x509_parser::extensions::ParsedExtension;

use crate::AdcsError;

/// `id-signedData` (RFC 5652 5.1).
const SIGNED_DATA_OID: &str = "1.2.840.113549.1.7.2";

fn chain_error(reason: impl Into<String>) -> AdcsError {
    AdcsError::Chain {
        reason: reason.into(),
    }
}

/// The issuing chain of `leaf_der` from the CMS `ContentInfo`
/// `cmc_der`: the certificates from the leaf's issuer upwards, in path
/// order, DER, without the self-signed root. The leaf itself, if the set
/// carries it, is not repeated.
///
/// Each link is the certificate whose subject is the current
/// certificate's issuer, and when both carry key identifiers, whose
/// subject key identifier equals the current authority key identifier;
/// two CAs with the same name are told apart that way. The walk stops
/// at a self-signed certificate, which is dropped, or where the set has
/// no issuer, which keeps the chain up to there. A set holding no issuer
/// of the leaf at all is refused.
pub fn chain_from_cmc(leaf_der: &[u8], cmc_der: &[u8]) -> Result<Vec<Vec<u8>>, AdcsError> {
    let (_, leaf): (&[u8], X509Certificate<'_>) = x509_parser::parse_x509_certificate(leaf_der)
        .map_err(|err| chain_error(format!("the issued certificate does not parse: {err}")))?;
    let set: Vec<&[u8]> = signed_data_certificates(cmc_der)?;
    let mut candidates: Vec<(&[u8], X509Certificate<'_>)> = Vec::with_capacity(set.len());
    for der in set {
        if der == leaf_der {
            continue;
        }
        let (_, cert): (&[u8], X509Certificate<'_>) = x509_parser::parse_x509_certificate(der)
            .map_err(|err| {
                chain_error(format!(
                    "a certificate of the CMC set does not parse: {err}"
                ))
            })?;
        candidates.push((der, cert));
    }

    let mut chain: Vec<Vec<u8>> = Vec::new();
    let mut used: Vec<bool> = vec![false; candidates.len()];
    let mut current: &X509Certificate<'_> = &leaf;
    loop {
        if is_self_issued(current) {
            break;
        }
        let next: Option<usize> = (0..candidates.len())
            .find(|index: &usize| !used[*index] && issues(&candidates[*index].1, current));
        let Some(index) = next else {
            break;
        };
        used[index] = true;
        let (der, issuer) = &candidates[index];
        if is_self_issued(issuer) {
            break;
        }
        chain.push(der.to_vec());
        current = issuer;
    }
    if chain.is_empty() && !used.iter().any(|was_used: &bool| *was_used) {
        return Err(chain_error(
            "no certificate of the CMC set issued the certificate",
        ));
    }
    Ok(chain)
}

fn authority_key_id<'a>(cert: &'a X509Certificate<'_>) -> Option<&'a [u8]> {
    cert.extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::AuthorityKeyIdentifier(aki) => {
                aki.key_identifier.as_ref().map(|id| id.0)
            }
            _ => None,
        })
}

fn subject_key_id<'a>(cert: &'a X509Certificate<'_>) -> Option<&'a [u8]> {
    cert.extensions()
        .iter()
        .find_map(|extension| match extension.parsed_extension() {
            ParsedExtension::SubjectKeyIdentifier(ski) => Some(ski.0),
            _ => None,
        })
}

/// Whether `issuer` is a plausible issuer of `subject`: names first,
/// key identifiers when both sides have them.
fn issues(issuer: &X509Certificate<'_>, subject: &X509Certificate<'_>) -> bool {
    if issuer.subject().as_raw() != subject.issuer().as_raw() {
        return false;
    }
    match (authority_key_id(subject), subject_key_id(issuer)) {
        (Some(aki), Some(ski)) => aki == ski,
        _ => true,
    }
}

fn is_self_issued(cert: &X509Certificate<'_>) -> bool {
    issues(cert, cert)
}

/// The DER of each certificate in the `certificates` field of the CMS
/// `SignedData` held by the `ContentInfo` `der` (RFC 5652 5.1):
///
/// ```text
/// ContentInfo ::= SEQUENCE { contentType OID, content [0] EXPLICIT ANY }
/// SignedData ::= SEQUENCE { version, digestAlgorithms SET,
///     encapContentInfo SEQUENCE, certificates [0] IMPLICIT SET OF
///     CertificateChoices OPTIONAL, crls [1] IMPLICIT OPTIONAL,
///     signerInfos SET }
/// ```
///
/// Choices other than a plain certificate (attribute and other
/// certificate formats) are skipped.
fn signed_data_certificates(der: &[u8]) -> Result<Vec<&[u8]>, AdcsError> {
    let content_info: Vec<&[u8]> = constructed_children(der, Class::Universal, Tag::Sequence)
        .map_err(|reason| {
            chain_error(format!("the CMC response is not a ContentInfo: {reason}"))
        })?;
    let [content_type, content] = content_info.as_slice() else {
        return Err(chain_error("the ContentInfo does not have two fields"));
    };
    let (_, oid): (&[u8], Oid<'_>) = Oid::from_der(content_type)
        .map_err(|err| chain_error(format!("the ContentInfo type is not an OID: {err}")))?;
    if oid.to_id_string() != SIGNED_DATA_OID {
        return Err(chain_error(format!(
            "the CMC response is {}, not SignedData",
            oid.to_id_string()
        )));
    }
    let explicit: Vec<&[u8]> = constructed_children(content, Class::ContextSpecific, Tag(0))
        .map_err(|reason| chain_error(format!("the ContentInfo content is malformed: {reason}")))?;
    let [signed_data] = explicit.as_slice() else {
        return Err(chain_error("the ContentInfo content is not one SignedData"));
    };
    let fields: Vec<&[u8]> = constructed_children(signed_data, Class::Universal, Tag::Sequence)
        .map_err(|reason| chain_error(format!("the SignedData is malformed: {reason}")))?;
    // version, digestAlgorithms and encapContentInfo come first; the
    // optional [0] certificates, if any, is the next field.
    let Some(certificates) = fields
        .get(3)
        .filter(|field: &&&[u8]| is_tag(field, Class::ContextSpecific, Tag(0)))
    else {
        return Err(chain_error("the SignedData carries no certificates"));
    };
    let choices: Vec<&[u8]> = constructed_children(certificates, Class::ContextSpecific, Tag(0))
        .map_err(|reason| chain_error(format!("the certificate set is malformed: {reason}")))?;
    Ok(choices
        .into_iter()
        .filter(|choice: &&[u8]| is_tag(choice, Class::Universal, Tag::Sequence))
        .collect())
}

fn is_tag(der: &[u8], class: Class, tag: Tag) -> bool {
    Any::from_der(der)
        .map(|(_, any)| any.header.class() == class && any.header.tag() == tag)
        .unwrap_or(false)
}

/// The raw TLVs inside the constructed element `der`, which must be
/// exactly one element of `class` and `tag`.
fn constructed_children(der: &[u8], class: Class, tag: Tag) -> Result<Vec<&[u8]>, String> {
    let (rest, outer): (&[u8], Any<'_>) = Any::from_der(der).map_err(|err| err.to_string())?;
    if !rest.is_empty() {
        return Err("trailing bytes after the element".to_owned());
    }
    if outer.header.class() != class || outer.header.tag() != tag || !outer.header.is_constructed()
    {
        return Err(format!(
            "expected a constructed {class:?} {tag:?}, found {:?} {:?}",
            outer.header.class(),
            outer.header.tag()
        ));
    }
    let mut children: Vec<&[u8]> = Vec::new();
    let mut remaining: &[u8] = outer.data;
    while !remaining.is_empty() {
        let (after, _): (&[u8], Any<'_>) =
            Any::from_der(remaining).map_err(|err| err.to_string())?;
        children.push(&remaining[..remaining.len() - after.len()]);
        remaining = after;
    }
    Ok(children)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der::{tlv, TAG_SEQUENCE};
    use crate::test_support::{ca_params, leaf_signed_by, oid_der, signed_data, TestPki};
    use rcgen::{CertifiedIssuer, KeyPair, PKCS_ECDSA_P256_SHA256};

    #[test]
    fn unordered_set_with_root_and_leaf_gives_the_intermediate() {
        let pki: TestPki = TestPki::generate();
        for order in [
            vec![&pki.root, &pki.leaf, &pki.intermediate],
            vec![&pki.intermediate, &pki.root],
            vec![&pki.leaf, &pki.root, &pki.intermediate],
        ] {
            let set: Vec<&[u8]> = order.iter().map(|der: &&Vec<u8>| der.as_slice()).collect();
            let chain: Vec<Vec<u8>> = chain_from_cmc(&pki.leaf, &signed_data(&set)).expect("chain");
            assert_eq!(chain, vec![pki.intermediate.clone()]);
        }
    }

    #[test]
    fn two_intermediates_in_path_order_without_root() {
        let pki: TestPki = TestPki::generate();
        let sub_key: KeyPair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
        let sub: CertifiedIssuer<'static, KeyPair> =
            CertifiedIssuer::signed_by(ca_params("Test Sub CA"), sub_key, &pki.intermediate_issuer)
                .expect("sub ca");
        let leaf: Vec<u8> = leaf_signed_by(&sub, "web02.corp.example.org");
        let cmc: Vec<u8> = signed_data(&[&pki.root, &pki.intermediate, sub.der(), &leaf]);
        let chain: Vec<Vec<u8>> = chain_from_cmc(&leaf, &cmc).expect("chain");
        assert_eq!(chain, vec![sub.der().to_vec(), pki.intermediate.clone()]);
    }

    #[test]
    fn same_name_different_key_is_told_apart_by_key_identifiers() {
        let pki: TestPki = TestPki::generate();
        // A second CA with the very same subject name, but its own key.
        let impostor_key: KeyPair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
        let impostor: CertifiedIssuer<'static, KeyPair> =
            CertifiedIssuer::self_signed(ca_params("Test Issuing CA"), impostor_key)
                .expect("impostor");
        let cmc: Vec<u8> = signed_data(&[impostor.der(), &pki.root, &pki.intermediate]);
        let chain: Vec<Vec<u8>> = chain_from_cmc(&pki.leaf, &cmc).expect("chain");
        assert_eq!(chain, vec![pki.intermediate.clone()]);
    }

    #[test]
    fn a_set_that_does_not_chain_to_the_leaf_is_refused() {
        let pki: TestPki = TestPki::generate();
        let other: TestPki = TestPki::generate();
        for set in [
            vec![other.root.as_slice(), other.intermediate.as_slice()],
            vec![pki.leaf.as_slice()],
            vec![],
        ] {
            assert!(matches!(
                chain_from_cmc(&pki.leaf, &signed_data(&set)),
                Err(AdcsError::Chain { .. })
            ));
        }
    }

    #[test]
    fn a_leaf_issued_by_the_root_directly_has_an_empty_chain() {
        let pki: TestPki = TestPki::generate();
        let root_key: KeyPair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("key");
        let root: CertifiedIssuer<'static, KeyPair> =
            CertifiedIssuer::self_signed(ca_params("Test Root Only"), root_key).expect("root");
        let leaf: Vec<u8> = leaf_signed_by(&root, "web03.corp.example.org");
        let chain: Vec<Vec<u8>> =
            chain_from_cmc(&leaf, &signed_data(&[root.der(), &pki.root])).expect("chain");
        assert!(chain.is_empty());
    }

    #[test]
    fn content_that_is_not_signed_data_is_refused() {
        let pki: TestPki = TestPki::generate();
        // id-data instead of id-signedData.
        let wrong_type: Vec<u8> = tlv(
            TAG_SEQUENCE,
            &[oid_der("1.2.840.113549.1.7.1"), tlv(0xA0, &tlv(0x04, &[]))].concat(),
        );
        for cmc in [
            wrong_type,
            b"\x30\x00".to_vec(),
            b"garbage".to_vec(),
            Vec::new(),
        ] {
            assert!(matches!(
                chain_from_cmc(&pki.leaf, &cmc),
                Err(AdcsError::Chain { .. })
            ));
        }
        // SignedData without a certificate set.
        let no_certs: Vec<u8> = {
            let full: Vec<u8> = signed_data(&[&pki.intermediate]);
            let content: Vec<u8> = crate::test_support::der_split(&full)[1].to_vec();
            let signed: &[u8] = crate::test_support::der_split(&content)[0];
            let fields: Vec<&[u8]> = crate::test_support::der_split(signed);
            let without: Vec<u8> = [fields[0], fields[1], fields[2], fields[4]].concat();
            tlv(
                TAG_SEQUENCE,
                &[
                    oid_der(SIGNED_DATA_OID),
                    tlv(0xA0, &tlv(TAG_SEQUENCE, &without)),
                ]
                .concat(),
            )
        };
        assert!(matches!(
            chain_from_cmc(&pki.leaf, &no_certs),
            Err(AdcsError::Chain { reason }) if reason.contains("no certificates")
        ));
    }
}
