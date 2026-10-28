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

//! Fixtures shared by the unit tests: DER helpers, a throwaway PKI
//! generated at test time, and the CMC response and WS-Trust bodies the
//! authority would send, built to the structure of MS-WSTEP 4.1.1.2 and
//! 3.1.4.1.3.7 rather than copied from the specification.

use base64::Engine as _;
use rcgen::{
    BasicConstraints, CertificateParams, CertifiedIssuer, DnType, IsCa, KeyPair,
    PKCS_ECDSA_P256_SHA256,
};
use x509_parser::der_parser::asn1_rs::{Any, FromDer};

use crate::der::{tlv, TAG_SEQUENCE, TAG_SET};
use crate::wstep::{
    BASE64_ENCODING_TYPE, ENROLLMENT_NS, PKCS7_VALUE_TYPE, SOAP_ENVELOPE_NS, WSSE_NS, WS_TRUST_NS,
    X509V3_VALUE_TYPE,
};

/// The raw TLVs inside the constructed DER element `der`.
pub(crate) fn der_split(der: &[u8]) -> Vec<&[u8]> {
    let (_, outer): (&[u8], Any<'_>) = Any::from_der(der).expect("outer TLV");
    let mut rest: &[u8] = outer.data;
    let mut children: Vec<&[u8]> = Vec::new();
    while !rest.is_empty() {
        let (after, _): (&[u8], Any<'_>) = Any::from_der(rest).expect("child TLV");
        children.push(&rest[..rest.len() - after.len()]);
        rest = after;
    }
    children
}

/// The DER `OBJECT IDENTIFIER` TLV of a dotted OID.
pub(crate) fn oid_der(dotted: &str) -> Vec<u8> {
    let arcs: Vec<u64> = dotted
        .split('.')
        .map(|arc: &str| arc.parse().expect("numeric arc"))
        .collect();
    let mut content: Vec<u8> = Vec::new();
    let mut push_base128 = |mut value: u64| {
        let mut groups: Vec<u8> = vec![(value & 0x7F) as u8];
        value >>= 7;
        while value > 0 {
            groups.push(0x80 | (value & 0x7F) as u8);
            value >>= 7;
        }
        groups.reverse();
        content.extend_from_slice(&groups);
    };
    push_base128(arcs[0] * 40 + arcs[1]);
    for arc in &arcs[2..] {
        push_base128(*arc);
    }
    tlv(0x06, &content)
}

pub(crate) fn b64(der: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(der)
}

/// A root, an intermediate and a leaf, all ECDSA P-256, generated per
/// test run. The intermediate and the leaf carry an authority key
/// identifier.
pub(crate) struct TestPki {
    pub(crate) root: Vec<u8>,
    pub(crate) intermediate: Vec<u8>,
    pub(crate) leaf: Vec<u8>,
    pub(crate) intermediate_issuer: CertifiedIssuer<'static, KeyPair>,
}

pub(crate) fn ca_params(common_name: &str) -> CertificateParams {
    let mut params: CertificateParams = CertificateParams::default();
    params.distinguished_name = rcgen::DistinguishedName::new();
    params
        .distinguished_name
        .push(DnType::CommonName, common_name);
    params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    params.use_authority_key_identifier_extension = true;
    params
}

pub(crate) fn leaf_signed_by(issuer: &CertifiedIssuer<'static, KeyPair>, name: &str) -> Vec<u8> {
    let key: KeyPair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("leaf key");
    let mut params: CertificateParams =
        CertificateParams::new(vec![name.to_owned()]).expect("leaf params");
    params.distinguished_name = rcgen::DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, name);
    params.use_authority_key_identifier_extension = true;
    params
        .signed_by(&key, issuer)
        .expect("sign leaf")
        .der()
        .to_vec()
}

impl TestPki {
    pub(crate) fn generate() -> TestPki {
        let root_key: KeyPair = KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("root key");
        let mut root_params: CertificateParams = ca_params("Test Root CA");
        root_params.use_authority_key_identifier_extension = false;
        let root: CertifiedIssuer<'static, KeyPair> =
            CertifiedIssuer::self_signed(root_params, root_key).expect("root");
        let intermediate_key: KeyPair =
            KeyPair::generate_for(&PKCS_ECDSA_P256_SHA256).expect("intermediate key");
        let intermediate: CertifiedIssuer<'static, KeyPair> =
            CertifiedIssuer::signed_by(ca_params("Test Issuing CA"), intermediate_key, &root)
                .expect("intermediate");
        let leaf: Vec<u8> = leaf_signed_by(&intermediate, "web01.corp.example.org");
        TestPki {
            root: root.der().to_vec(),
            intermediate: intermediate.der().to_vec(),
            leaf,
            intermediate_issuer: intermediate,
        }
    }
}

/// A minimal CMS `ContentInfo` holding a `SignedData` whose
/// `certificates` field carries `certificates` in the given order,
/// shaped like the CMC Full PKI Response of MS-WSTEP 4.1.1.2: an
/// `id-cct-PKIResponse` encapsulated content (left empty here) and no
/// signer, since the client reads the certificate set only.
pub(crate) fn signed_data(certificates: &[&[u8]]) -> Vec<u8> {
    let version: Vec<u8> = tlv(0x02, &[0x03]);
    let digest_algorithms: Vec<u8> = tlv(TAG_SET, &[]);
    let encap_content_info: Vec<u8> = tlv(TAG_SEQUENCE, &oid_der("1.3.6.1.5.5.7.12.3"));
    let certificate_set: Vec<u8> = tlv(0xA0, &certificates.concat());
    let signer_infos: Vec<u8> = tlv(TAG_SET, &[]);
    let signed: Vec<u8> = tlv(
        TAG_SEQUENCE,
        &[
            version,
            digest_algorithms,
            encap_content_info,
            certificate_set,
            signer_infos,
        ]
        .concat(),
    );
    tlv(
        TAG_SEQUENCE,
        &[oid_der("1.2.840.113549.1.7.2"), tlv(0xA0, &signed)].concat(),
    )
}

/// Base64 broken into CRLF-separated lines of 64 characters, as a
/// Windows server may send it.
pub(crate) fn b64_crlf(der: &[u8]) -> String {
    let flat: String = b64(der);
    flat.as_bytes()
        .chunks(64)
        .map(|chunk: &[u8]| String::from_utf8_lossy(chunk).into_owned())
        .collect::<Vec<String>>()
        .join("\r\n")
}

/// The body of an issued response (MS-WSTEP 4.1.1.2). Prefixes differ
/// from the request's on purpose: the parser must key on namespaces.
pub(crate) fn issued_response(leaf: &[u8], cmc: &[u8], request_id: &str) -> String {
    format!(
        r#"<env:Envelope xmlns:env="{SOAP_ENVELOPE_NS}" xmlns:wsa="http://www.w3.org/2005/08/addressing"><env:Header><wsa:Action env:mustUnderstand="1">http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RSTRC/wstep</wsa:Action><wsa:RelatesTo>urn:uuid:00000000-0000-4000-8000-000000000000</wsa:RelatesTo></env:Header><env:Body><RequestSecurityTokenResponseCollection xmlns="{WS_TRUST_NS}"><RequestSecurityTokenResponse><TokenType>{X509V3_VALUE_TYPE}</TokenType><DispositionMessage xml:lang="en-US" xmlns="{ENROLLMENT_NS}">Issued</DispositionMessage><BinarySecurityToken ValueType="{PKCS7_VALUE_TYPE}" EncodingType="{BASE64_ENCODING_TYPE}" xmlns="{WSSE_NS}">{cmc}</BinarySecurityToken><RequestedSecurityToken><BinarySecurityToken ValueType="{X509V3_VALUE_TYPE}" EncodingType="{BASE64_ENCODING_TYPE}" xmlns="{WSSE_NS}">{leaf}</BinarySecurityToken></RequestedSecurityToken><RequestID xmlns="{ENROLLMENT_NS}">{request_id}</RequestID></RequestSecurityTokenResponse></RequestSecurityTokenResponseCollection></env:Body></env:Envelope>"#,
        cmc = b64_crlf(cmc),
        leaf = b64_crlf(leaf),
    )
}

/// The body of a pending response: a reference instead of a
/// certificate, and a request identifier (MS-WSTEP 3.1.4.1.3.2).
pub(crate) fn pending_response(request_id: &str) -> String {
    format!(
        r#"<s:Envelope xmlns:s="{SOAP_ENVELOPE_NS}"><s:Body><RequestSecurityTokenResponseCollection xmlns="{WS_TRUST_NS}"><RequestSecurityTokenResponse><TokenType>{X509V3_VALUE_TYPE}</TokenType><DispositionMessage xmlns="{ENROLLMENT_NS}">Taken Under Submission</DispositionMessage><RequestedSecurityToken><o:SecurityTokenReference xmlns:o="{WSSE_NS}"><o:Reference URI="https://ces.corp.example.org/CES"/></o:SecurityTokenReference></RequestedSecurityToken><RequestID xmlns="{ENROLLMENT_NS}">{request_id}</RequestID></RequestSecurityTokenResponse></RequestSecurityTokenResponseCollection></s:Body></s:Envelope>"#
    )
}

/// A SOAP 1.2 fault (MS-WSTEP 4.1.4.2) with, when `detail` is given, a
/// `CertificateEnrollmentWSDetail` (3.1.4.1.3.7) of `(error_code,
/// invalid_request, request_id)`.
pub(crate) fn fault_response(reason: &str, detail: Option<(i32, bool, &str)>) -> String {
    let detail: String = match detail {
        None => String::new(),
        Some((code, invalid, request_id)) => format!(
            r#"<s:Detail><CertificateEnrollmentWSDetail xmlns="{ENROLLMENT_NS}" xmlns:i="http://www.w3.org/2001/XMLSchema-instance"><BinaryResponse i:nil="true"/><ErrorCode>{code}</ErrorCode><InvalidRequest>{invalid}</InvalidRequest><RequestID>{request_id}</RequestID></CertificateEnrollmentWSDetail></s:Detail>"#
        ),
    };
    format!(
        r#"<s:Envelope xmlns:s="{SOAP_ENVELOPE_NS}" xmlns:a="http://www.w3.org/2005/08/addressing"><s:Header><a:Action s:mustUnderstand="1">http://schemas.microsoft.com/net/2005/12/windowscommunicationfoundation/dispatcher/fault</a:Action></s:Header><s:Body><s:Fault><s:Code><s:Value>s:Receiver</s:Value></s:Code><s:Reason><s:Text xml:lang="en-US">{reason}</s:Text></s:Reason>{detail}</s:Fault></s:Body></s:Envelope>"#
    )
}
