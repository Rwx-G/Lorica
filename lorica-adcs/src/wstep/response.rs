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

//! Reading the authority's answer: a `RequestSecurityTokenResponseCollection`
//! (MS-WSTEP 3.1.4.1.3.4, 3.1.4.1.3.5, 4.1.1.2) or a SOAP 1.2 fault with
//! an optional `CertificateEnrollmentWSDetail` (3.1.4.1.2.1, 3.1.4.1.3.7).
//!
//! Elements are matched on namespace URI and local name, never on the
//! prefix, which differs between servers and between examples.

use base64::Engine as _;
use quick_xml::events::{BytesStart, Event};
use quick_xml::name::{Namespace, ResolveResult};
use quick_xml::{NsReader, XmlVersion};

use super::{
    ENROLLMENT_NS, PKCS7_VALUE_TYPE, SOAP_ENVELOPE_NS, WSSE_NS, WS_TRUST_NS, X509V3_VALUE_TYPE,
    XSI_NS,
};
use crate::chain::chain_from_cmc;
use crate::AdcsError;

/// `CERTSRV_E_TEMPLATE_DENIED`: no Enroll permission on the template
/// (MS-WCCE 3.2.2.6.2.1.4.3).
const CERTSRV_E_TEMPLATE_DENIED: u32 = 0x8009_4012;
/// `CERTSRV_E_UNSUPPORTED_CERT_TYPE`: the template is unknown or not
/// published, including a display name given for the common name.
const CERTSRV_E_UNSUPPORTED_CERT_TYPE: u32 = 0x8009_4800;
/// `CERTSRV_E_TEMPLATE_CONFLICT`: the request names two templates.
const CERTSRV_E_TEMPLATE_CONFLICT: u32 = 0x8009_4802;

/// A SOAP envelope is a handful of levels deep; anything far deeper is
/// not an answer from CES and is refused before it costs anything.
const MAX_DEPTH: usize = 64;

/// What a fault that is not a denial is about, from its `ErrorCode`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FaultKind {
    /// The service account lacks the Enroll permission on the template.
    Permission,
    /// The template is unknown, unpublished, or ambiguous.
    Template,
    /// Any other code, or no detail at all.
    Other,
}

/// The authority's answer to an enrollment request.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum EnrollmentResponse {
    /// A certificate was issued.
    Issued {
        /// The issued certificate, DER.
        leaf_der: Vec<u8>,
        /// The issuing chain in path order from the leaf's issuer
        /// upwards, DER, without the self-signed root.
        chain_der: Vec<Vec<u8>>,
        /// The authority's request identifier, when given.
        request_id: Option<String>,
        /// The authority's disposition text, when given.
        disposition_message: Option<String>,
    },
    /// The request awaits a certificate manager's approval. Templates
    /// that need it are not supported in v1.10.0; the identifier is kept
    /// so the operator can follow it up at the authority.
    Pending {
        /// The authority's request identifier.
        request_id: String,
    },
    /// The authority denied the request (`InvalidRequest` true).
    Denied {
        /// The HRESULT the authority gave, as unsigned.
        error_code: Option<u32>,
        /// The authority's request identifier, when given.
        request_id: Option<String>,
        /// The fault reason text.
        message: String,
    },
    /// Any other fault.
    Error {
        /// What the error code says the fault is about.
        kind: FaultKind,
        /// The HRESULT the authority gave, as unsigned.
        error_code: Option<u32>,
        /// The fault reason text.
        message: String,
    },
}

fn malformed(reason: impl Into<String>) -> AdcsError {
    AdcsError::SoapResponse {
        reason: reason.into(),
    }
}

/// Parses the body of the HTTP answer to an enrollment request. The
/// HTTP status is not looked at: a fault arrives with a status the
/// specification does not fix (500 in practice).
///
/// A body that is neither a `RequestSecurityTokenResponseCollection`
/// nor a SOAP fault is refused, as is an issued answer whose chain does
/// not lead to its certificate.
pub fn parse_response(body: &str) -> Result<EnrollmentResponse, AdcsError> {
    let envelope: Element = parse_tree(body)?;
    if !envelope.is(SOAP_ENVELOPE_NS, "Envelope") {
        return Err(malformed(format!(
            "the root element is {{{}}}{}, not a SOAP 1.2 Envelope",
            envelope.ns, envelope.local
        )));
    }
    let soap_body: &Element = envelope
        .child(SOAP_ENVELOPE_NS, "Body")
        .ok_or_else(|| malformed("the envelope has no Body"))?;
    let payload: &Element = soap_body
        .children
        .first()
        .ok_or_else(|| malformed("the SOAP Body is empty"))?;
    if payload.is(WS_TRUST_NS, "RequestSecurityTokenResponseCollection") {
        parse_collection(payload)
    } else if payload.is(SOAP_ENVELOPE_NS, "Fault") {
        parse_fault(payload)
    } else {
        Err(malformed(format!(
            "the SOAP Body holds {{{}}}{}, neither a RequestSecurityTokenResponseCollection nor a Fault",
            payload.ns, payload.local
        )))
    }
}

fn parse_collection(collection: &Element) -> Result<EnrollmentResponse, AdcsError> {
    let mut responses = collection.children_named(WS_TRUST_NS, "RequestSecurityTokenResponse");
    let response: &Element = responses
        .next()
        .ok_or_else(|| malformed("the collection holds no RequestSecurityTokenResponse"))?;
    if responses.next().is_some() {
        return Err(malformed(
            "the collection holds more than one RequestSecurityTokenResponse (MS-WSTEP 3.1.4.1.3.5)",
        ));
    }
    let request_id: Option<String> = response
        .child(ENROLLMENT_NS, "RequestID")
        .and_then(Element::non_nil_text);
    let disposition_message: Option<String> = response
        .child(ENROLLMENT_NS, "DispositionMessage")
        .and_then(Element::non_nil_text);

    let requested_token: Option<&Element> = response.child(WS_TRUST_NS, "RequestedSecurityToken");
    let leaf_token: Option<&Element> =
        requested_token.and_then(|token: &Element| token.child(WSSE_NS, "BinarySecurityToken"));
    let Some(leaf_token) = leaf_token else {
        // MS-WSTEP has no pending example: key on "no certificate and a
        // request identifier", not on the shape of the reference.
        return match request_id {
            Some(request_id) => Ok(EnrollmentResponse::Pending { request_id }),
            None => Err(malformed(
                "the response carries neither a certificate nor a RequestID",
            )),
        };
    };
    if leaf_token.attr("", "ValueType") != Some(X509V3_VALUE_TYPE) {
        return Err(malformed(
            "the RequestedSecurityToken is not an X509v3 BinarySecurityToken",
        ));
    }
    let leaf_der: Vec<u8> = decode_base64(&leaf_token.text, "the issued certificate")?;
    let cmc_token: &Element = response
        .children_named(WSSE_NS, "BinarySecurityToken")
        .find(|token: &&Element| token.attr("", "ValueType") == Some(PKCS7_VALUE_TYPE))
        .ok_or_else(|| {
            malformed(
                "the response carries no CMC (PKCS7) BinarySecurityToken beside the certificate",
            )
        })?;
    let cmc_der: Vec<u8> = decode_base64(&cmc_token.text, "the CMC response")?;
    let chain_der: Vec<Vec<u8>> = chain_from_cmc(&leaf_der, &cmc_der)?;
    Ok(EnrollmentResponse::Issued {
        leaf_der,
        chain_der,
        request_id,
        disposition_message,
    })
}

fn parse_fault(fault: &Element) -> Result<EnrollmentResponse, AdcsError> {
    let message: String = fault
        .child(SOAP_ENVELOPE_NS, "Reason")
        .and_then(|reason: &Element| reason.child(SOAP_ENVELOPE_NS, "Text"))
        .map(|text: &Element| text.text.trim().to_owned())
        .unwrap_or_default();
    let detail: Option<&Element> = fault
        .child(SOAP_ENVELOPE_NS, "Detail")
        .and_then(|detail: &Element| detail.child(ENROLLMENT_NS, "CertificateEnrollmentWSDetail"));
    let Some(detail) = detail else {
        return Ok(EnrollmentResponse::Error {
            kind: FaultKind::Other,
            error_code: None,
            message,
        });
    };
    let error_code: Option<u32> = match detail
        .child(ENROLLMENT_NS, "ErrorCode")
        .and_then(Element::non_nil_text)
    {
        // xs:int on the wire: an HRESULT read as signed, so 0x80094012
        // arrives as -2146877422. The bit pattern is what is compared.
        Some(text) => Some(
            text.parse::<i32>()
                .map_err(|_| malformed(format!("ErrorCode {text:?} is not an xs:int")))?
                as u32,
        ),
        None => None,
    };
    let invalid_request: bool = match detail
        .child(ENROLLMENT_NS, "InvalidRequest")
        .and_then(Element::non_nil_text)
        .as_deref()
    {
        None | Some("false") | Some("0") => false,
        Some("true") | Some("1") => true,
        Some(other) => {
            return Err(malformed(format!(
                "InvalidRequest {other:?} is not an xs:boolean"
            )))
        }
    };
    if invalid_request {
        return Ok(EnrollmentResponse::Denied {
            error_code,
            request_id: detail
                .child(ENROLLMENT_NS, "RequestID")
                .and_then(Element::non_nil_text),
            message,
        });
    }
    let kind: FaultKind = match error_code {
        Some(CERTSRV_E_TEMPLATE_DENIED) => FaultKind::Permission,
        Some(CERTSRV_E_UNSUPPORTED_CERT_TYPE | CERTSRV_E_TEMPLATE_CONFLICT) => FaultKind::Template,
        _ => FaultKind::Other,
    };
    Ok(EnrollmentResponse::Error {
        kind,
        error_code,
        message,
    })
}

/// Base64 as Windows sends it: wrapped with CR/LF, sometimes with stray
/// spaces. Every ASCII whitespace is dropped before decoding.
fn decode_base64(text: &str, what: &str) -> Result<Vec<u8>, AdcsError> {
    let compact: String = text
        .chars()
        .filter(|c: &char| !c.is_ascii_whitespace())
        .collect();
    if compact.is_empty() {
        return Err(malformed(format!("{what} is empty")));
    }
    base64::engine::general_purpose::STANDARD
        .decode(compact.as_bytes())
        .map_err(|err| malformed(format!("{what} is not valid base64: {err}")))
}

/// One element of the parsed document: its expanded name, attributes
/// with their expanded names, character data and child elements.
#[derive(Debug)]
struct Element {
    ns: String,
    local: String,
    attrs: Vec<(String, String, String)>,
    text: String,
    children: Vec<Element>,
}

impl Element {
    fn is(&self, ns: &str, local: &str) -> bool {
        self.ns == ns && self.local == local
    }

    fn child(&self, ns: &str, local: &str) -> Option<&Element> {
        self.children
            .iter()
            .find(|child: &&Element| child.is(ns, local))
    }

    fn children_named<'a>(
        &'a self,
        ns: &'a str,
        local: &'a str,
    ) -> impl Iterator<Item = &'a Element> + 'a {
        self.children
            .iter()
            .filter(move |child: &&Element| child.is(ns, local))
    }

    /// An attribute by expanded name; `ns` is empty for an unprefixed
    /// attribute, which XML Namespaces leaves in no namespace.
    fn attr(&self, ns: &str, local: &str) -> Option<&str> {
        self.attrs
            .iter()
            .find(|(attr_ns, attr_local, _)| attr_ns == ns && attr_local == local)
            .map(|(_, _, value)| value.as_str())
    }

    /// The trimmed text, or `None` when the element is `xsi:nil` or
    /// empty.
    fn non_nil_text(&self) -> Option<String> {
        if matches!(self.attr(XSI_NS, "nil"), Some("true" | "1")) {
            return None;
        }
        let text: &str = self.text.trim();
        (!text.is_empty()).then(|| text.to_owned())
    }
}

fn namespace_of(resolved: &ResolveResult<'_>) -> Result<String, AdcsError> {
    match resolved {
        ResolveResult::Bound(Namespace(ns)) => Ok((*ns).to_owned()),
        ResolveResult::Unbound => Ok(String::new()),
        ResolveResult::Unknown(prefix) => Err(malformed(format!(
            "the prefix {prefix:?} is not bound to a namespace"
        ))),
    }
}

fn open_element(
    reader: &NsReader<&[u8]>,
    ns: String,
    start: &BytesStart<'_>,
) -> Result<Element, AdcsError> {
    let mut attrs: Vec<(String, String, String)> = Vec::new();
    for attr in start.attributes() {
        let attr = attr.map_err(|err| malformed(format!("bad attribute: {err}")))?;
        if attr.key.as_namespace_binding().is_some() {
            continue;
        }
        let (resolved, local) = reader.resolver().resolve_attribute(attr.key);
        let attr_ns: String = namespace_of(&resolved)?;
        let value: String = attr
            .normalized_value(XmlVersion::Implicit1_0)
            .map_err(|err| malformed(format!("bad attribute value: {err}")))?
            .into_owned();
        attrs.push((attr_ns, local.as_ref().to_owned(), value));
    }
    Ok(Element {
        ns,
        local: start.local_name().as_ref().to_owned(),
        attrs,
        text: String::new(),
        children: Vec::new(),
    })
}

fn close_element(
    element: Element,
    stack: &mut [Element],
    root: &mut Option<Element>,
) -> Result<(), AdcsError> {
    match stack.last_mut() {
        Some(parent) => parent.children.push(element),
        None if root.is_none() => *root = Some(element),
        None => return Err(malformed("more than one root element")),
    }
    Ok(())
}

fn parse_tree(body: &str) -> Result<Element, AdcsError> {
    let mut reader: NsReader<&[u8]> = NsReader::from_str(body);
    let mut stack: Vec<Element> = Vec::new();
    let mut root: Option<Element> = None;
    loop {
        let (resolved, event) = reader
            .read_resolved_event()
            .map_err(|err| malformed(format!("not well-formed XML: {err}")))?;
        let ns: Option<String> = match &event {
            Event::Start(_) | Event::Empty(_) => Some(namespace_of(&resolved)?),
            _ => None,
        };
        match event {
            Event::Start(start) => {
                let element: Element = open_element(&reader, ns.unwrap_or_default(), &start)?;
                stack.push(element);
                if stack.len() > MAX_DEPTH {
                    return Err(malformed("the document is nested too deeply"));
                }
            }
            Event::Empty(start) => {
                let element: Element = open_element(&reader, ns.unwrap_or_default(), &start)?;
                close_element(element, &mut stack, &mut root)?;
            }
            Event::End(_) => {
                let element: Element = stack
                    .pop()
                    .ok_or_else(|| malformed("an end tag closes nothing"))?;
                close_element(element, &mut stack, &mut root)?;
            }
            Event::Text(text) => append_text(&mut stack, &text.xml10_content())?,
            Event::CData(data) => append_text(&mut stack, &data.xml10_content())?,
            Event::GeneralRef(reference) => {
                let resolved: String = match reference
                    .resolve_char_ref()
                    .map_err(|err| malformed(format!("bad character reference: {err}")))?
                {
                    Some(c) => c.to_string(),
                    None => quick_xml::escape::resolve_predefined_entity(&reference)
                        .ok_or_else(|| malformed(format!("unknown entity &{};", &*reference)))?
                        .to_owned(),
                };
                append_text(&mut stack, &resolved)?;
            }
            // SOAP 1.2 forbids a DTD (Part 1, 5): refusing it also keeps
            // entity definitions out of reach.
            Event::DocType(_) => return Err(malformed("a DOCTYPE is not allowed in SOAP")),
            Event::Decl(_) | Event::Comment(_) | Event::PI(_) => {}
            Event::Eof => break,
        }
    }
    if !stack.is_empty() {
        return Err(malformed("the document ends inside an element"));
    }
    root.ok_or_else(|| malformed("the body is not an XML document"))
}

fn append_text(stack: &mut [Element], text: &str) -> Result<(), AdcsError> {
    match stack.last_mut() {
        Some(current) => current.text.push_str(text),
        None if text.trim().is_empty() => {}
        None => return Err(malformed("text outside the root element")),
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{
        b64, fault_response, issued_response, pending_response, signed_data, TestPki,
    };

    #[test]
    fn issued_with_an_unordered_cmc_set_that_includes_the_root() {
        let pki: TestPki = TestPki::generate();
        let cmc: Vec<u8> = signed_data(&[&pki.root, &pki.leaf, &pki.intermediate]);
        let body: String = issued_response(&pki.leaf, &cmc, "61");
        assert!(body.contains("\r\n"), "fixture base64 must carry CRLF");
        match parse_response(&body).expect("issued") {
            EnrollmentResponse::Issued {
                leaf_der,
                chain_der,
                request_id,
                disposition_message,
            } => {
                assert_eq!(leaf_der, pki.leaf);
                assert_eq!(chain_der, vec![pki.intermediate.clone()]);
                assert_eq!(request_id.as_deref(), Some("61"));
                assert_eq!(disposition_message.as_deref(), Some("Issued"));
            }
            other => panic!("expected issued, got {other:?}"),
        }
    }

    #[test]
    fn pending_keeps_the_request_id() {
        assert_eq!(
            parse_response(&pending_response("4242")).expect("pending"),
            EnrollmentResponse::Pending {
                request_id: "4242".to_owned()
            }
        );
    }

    #[test]
    fn denial_fault() {
        let body: String = fault_response(
            "Denied by Policy Module",
            Some((0x8009_4012_u32 as i32, true, "77")),
        );
        assert_eq!(
            parse_response(&body).expect("denied"),
            EnrollmentResponse::Denied {
                error_code: Some(0x8009_4012),
                request_id: Some("77".to_owned()),
                message: "Denied by Policy Module".to_owned(),
            }
        );
    }

    #[test]
    fn error_faults_are_classified_by_code() {
        let cases: [(u32, FaultKind); 4] = [
            (CERTSRV_E_TEMPLATE_DENIED, FaultKind::Permission),
            (CERTSRV_E_UNSUPPORTED_CERT_TYPE, FaultKind::Template),
            (CERTSRV_E_TEMPLATE_CONFLICT, FaultKind::Template),
            (0x8007_0005, FaultKind::Other),
        ];
        for (code, kind) in cases {
            let body: String =
                fault_response("CES refused the request", Some((code as i32, false, "")));
            assert_eq!(
                parse_response(&body).expect("fault"),
                EnrollmentResponse::Error {
                    kind,
                    error_code: Some(code),
                    message: "CES refused the request".to_owned(),
                },
                "code {code:#x}"
            );
        }
    }

    #[test]
    fn error_code_arrives_signed() {
        // The literal is the decimal form a WCF server writes for
        // 0x80094012.
        let body: String = fault_response("x", Some((0, false, ""))).replace(
            "<ErrorCode>0</ErrorCode>",
            "<ErrorCode>-2146877422</ErrorCode>",
        );
        assert!(matches!(
            parse_response(&body).expect("fault"),
            EnrollmentResponse::Error {
                kind: FaultKind::Permission,
                error_code: Some(0x8009_4012),
                ..
            }
        ));
    }

    #[test]
    fn fault_without_detail_is_a_generic_error() {
        let body: String = fault_response(
            "The server was unable to process the request due to an internal error &lt;x&gt;.",
            None,
        );
        assert_eq!(
            parse_response(&body).expect("fault"),
            EnrollmentResponse::Error {
                kind: FaultKind::Other,
                error_code: None,
                message:
                    "The server was unable to process the request due to an internal error <x>."
                        .to_owned(),
            }
        );
    }

    #[test]
    fn nil_detail_fields_are_absent() {
        let body: String = fault_response("x", Some((0, false, "")))
            .replace("<ErrorCode>0</ErrorCode>", r#"<ErrorCode i:nil="true"/>"#);
        assert!(matches!(
            parse_response(&body).expect("fault"),
            EnrollmentResponse::Error {
                kind: FaultKind::Other,
                error_code: None,
                ..
            }
        ));
    }

    #[test]
    fn prefixes_do_not_matter_namespaces_do() {
        let pki: TestPki = TestPki::generate();
        let cmc: Vec<u8> = signed_data(&[&pki.intermediate, &pki.root]);
        let body: String = issued_response(&pki.leaf, &cmc, "61");
        let renamed: String = body
            .replace("env:", "soap12:")
            .replace("xmlns:env=", "xmlns:soap12=");
        assert!(matches!(
            parse_response(&renamed).expect("issued"),
            EnrollmentResponse::Issued { .. }
        ));
        // Same local names in the wrong namespace are not the envelope.
        let wrong_ns: String = body.replace(
            "http://www.w3.org/2003/05/soap-envelope",
            "http://schemas.xmlsoap.org/soap/envelope/",
        );
        assert!(matches!(
            parse_response(&wrong_ns),
            Err(AdcsError::SoapResponse { .. })
        ));
    }

    #[test]
    fn base64_tolerates_crlf_and_spaces() {
        let pki: TestPki = TestPki::generate();
        let cmc: Vec<u8> = signed_data(&[&pki.intermediate]);
        let spaced_leaf: String = b64(&pki.leaf)
            .as_bytes()
            .chunks(10)
            .map(|chunk: &[u8]| String::from_utf8_lossy(chunk).into_owned())
            .collect::<Vec<String>>()
            .join(" \r\n\t");
        let body: String = issued_response(&pki.leaf, &cmc, "1");
        let flat: String = crate::test_support::b64_crlf(&pki.leaf);
        let body: String = body.replacen(&flat, &spaced_leaf, 1);
        assert!(matches!(
            parse_response(&body).expect("issued"),
            EnrollmentResponse::Issued { leaf_der, .. } if leaf_der == pki.leaf
        ));
    }

    #[test]
    fn bodies_that_are_neither_rstrc_nor_fault_are_refused() {
        let pki: TestPki = TestPki::generate();
        let cmc: Vec<u8> = signed_data(&[&pki.intermediate]);
        let issued: String = issued_response(&pki.leaf, &cmc, "1");
        let cases: Vec<String> = vec![
            String::new(),
            "not xml".to_owned(),
            "<html><body>Bad Request</body></html>".to_owned(),
            format!(r#"<s:Envelope xmlns:s="{SOAP_ENVELOPE_NS}"><s:Body/></s:Envelope>"#),
            format!(
                r#"<s:Envelope xmlns:s="{SOAP_ENVELOPE_NS}"><s:Body><RequestSecurityTokenResponse xmlns="{WS_TRUST_NS}"/></s:Body></s:Envelope>"#
            ),
            format!(
                r#"<s:Envelope xmlns:s="{SOAP_ENVELOPE_NS}"><s:Body><RequestSecurityTokenResponseCollection xmlns="{WS_TRUST_NS}"/></s:Body></s:Envelope>"#
            ),
            // Two responses in one collection (MS-WSTEP 3.1.4.1.3.5).
            issued.replace(
                "</RequestSecurityTokenResponseCollection>",
                "<RequestSecurityTokenResponse/></RequestSecurityTokenResponseCollection>",
            ),
            // No certificate and no RequestID.
            pending_response(""),
            // The chain token is missing.
            issued.replace(PKCS7_VALUE_TYPE, "urn:other"),
            // Unknown entity and a DOCTYPE.
            format!(
                r#"<s:Envelope xmlns:s="{SOAP_ENVELOPE_NS}"><s:Body>&evil;</s:Body></s:Envelope>"#
            ),
            format!(r#"<!DOCTYPE x [<!ENTITY a "b">]><s:Envelope xmlns:s="{SOAP_ENVELOPE_NS}"/>"#),
            // Unbound prefix and a truncated document.
            "<s:Envelope><s:Body/></s:Envelope>".to_owned(),
            issued[..issued.len() / 2].to_owned(),
            // Malformed detail values.
            fault_response("x", Some((0, false, ""))).replace(
                "<ErrorCode>0</ErrorCode>",
                "<ErrorCode>0x80094012</ErrorCode>",
            ),
            fault_response("x", Some((0, false, ""))).replace(
                "<InvalidRequest>false</InvalidRequest>",
                "<InvalidRequest>maybe</InvalidRequest>",
            ),
        ];
        for body in cases {
            assert!(
                matches!(parse_response(&body), Err(AdcsError::SoapResponse { .. })),
                "accepted: {body}"
            );
        }
    }

    #[test]
    fn issued_with_a_chain_that_does_not_reach_the_leaf_is_refused() {
        let pki: TestPki = TestPki::generate();
        let other: TestPki = TestPki::generate();
        let cmc: Vec<u8> = signed_data(&[&other.intermediate, &other.root]);
        let body: String = issued_response(&pki.leaf, &cmc, "1");
        assert!(matches!(
            parse_response(&body),
            Err(AdcsError::Chain { .. })
        ));
    }

    #[test]
    fn deep_nesting_is_refused() {
        let body: String = format!(
            "{}{}",
            "<a>".repeat(MAX_DEPTH + 1),
            "</a>".repeat(MAX_DEPTH + 1)
        );
        assert!(matches!(
            parse_response(&body),
            Err(AdcsError::SoapResponse { reason }) if reason.contains("deeply")
        ));
    }
}
