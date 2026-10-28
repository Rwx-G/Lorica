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

//! The `RequestSecurityToken` envelope (MS-WSTEP 3.1.4.1.2, 4.1.1.1).

use base64::Engine as _;
use quick_xml::events::BytesText;
use quick_xml::Writer;

use super::{
    ANONYMOUS_ADDRESS, BASE64_ENCODING_TYPE, ENROLLMENT_NS, ISSUE_REQUEST_TYPE, PKCS7_VALUE_TYPE,
    RST_ACTION, SOAP_ENVELOPE_NS, WSSE_NS, WS_ADDRESSING_NS, WS_TRUST_NS, X509V3_VALUE_TYPE,
    XSI_NS,
};
use crate::AdcsError;

/// The `Content-Type` of the POST that carries the envelope.
pub(crate) const SOAP_CONTENT_TYPE: &str = "application/soap+xml; charset=utf-8";

/// A fresh WS-Addressing `MessageID`, `urn:uuid:` and a random (v4)
/// UUID.
pub(crate) fn new_message_id() -> String {
    format!("urn:uuid:{}", uuid::Uuid::new_v4())
}

/// The SOAP 1.2 envelope asking the CES at `endpoint_url` to issue a
/// certificate for the DER PKCS#10 `csr_der`, identified by
/// `message_id` (see [`new_message_id`]).
///
/// The envelope has no WS-Security header: in Kerberos mode CES
/// authenticates at the transport (MS-WSTEP 3.1.1.1.1). The template is
/// not here either; it travels inside the CSR. `a:To` is not in the
/// specification's example; other clients send it and it is harmless.
pub(crate) fn build_request(
    endpoint_url: &str,
    message_id: &str,
    csr_der: &[u8],
) -> Result<String, AdcsError> {
    let csr_base64: String = base64::engine::general_purpose::STANDARD.encode(csr_der);
    let mut writer: Writer<Vec<u8>> = Writer::new(Vec::new());
    writer
        .create_element("s:Envelope")
        .with_attribute(("xmlns:s", SOAP_ENVELOPE_NS))
        .with_attribute(("xmlns:a", WS_ADDRESSING_NS))
        .write_inner_content(|writer: &mut Writer<Vec<u8>>| {
            writer.create_element("s:Header").write_inner_content(
                |writer: &mut Writer<Vec<u8>>| {
                    writer
                        .create_element("a:Action")
                        .with_attribute(("s:mustUnderstand", "1"))
                        .write_text_content(BytesText::new(RST_ACTION))?;
                    writer
                        .create_element("a:MessageID")
                        .write_text_content(BytesText::new(message_id))?;
                    writer.create_element("a:ReplyTo").write_inner_content(
                        |writer: &mut Writer<Vec<u8>>| {
                            writer
                                .create_element("a:Address")
                                .write_text_content(BytesText::new(ANONYMOUS_ADDRESS))?;
                            Ok(())
                        },
                    )?;
                    writer
                        .create_element("a:To")
                        .write_text_content(BytesText::new(endpoint_url))?;
                    Ok(())
                },
            )?;
            writer
                .create_element("s:Body")
                .with_attribute(("xmlns:xsi", XSI_NS))
                .write_inner_content(|writer: &mut Writer<Vec<u8>>| {
                    writer
                        .create_element("RequestSecurityToken")
                        .with_attribute(("xmlns", WS_TRUST_NS))
                        .write_inner_content(|writer: &mut Writer<Vec<u8>>| {
                            writer
                                .create_element("TokenType")
                                .write_text_content(BytesText::new(X509V3_VALUE_TYPE))?;
                            writer
                                .create_element("RequestType")
                                .write_text_content(BytesText::new(ISSUE_REQUEST_TYPE))?;
                            writer
                                .create_element("BinarySecurityToken")
                                .with_attribute(("EncodingType", BASE64_ENCODING_TYPE))
                                .with_attribute(("ValueType", PKCS7_VALUE_TYPE))
                                .with_attribute(("xmlns", WSSE_NS))
                                .write_text_content(BytesText::new(&csr_base64))?;
                            writer
                                .create_element("RequestID")
                                .with_attribute(("xsi:nil", "true"))
                                .with_attribute(("xmlns", ENROLLMENT_NS))
                                .write_empty()?;
                            Ok(())
                        })?;
                    Ok(())
                })?;
            Ok(())
        })
        .map_err(|source: std::io::Error| AdcsError::SoapEnvelope { source })?;
    String::from_utf8(writer.into_inner()).map_err(|err| AdcsError::SoapEnvelope {
        source: std::io::Error::new(std::io::ErrorKind::InvalidData, err),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn envelope_matches_the_golden_file() {
        let csr: &[u8] = b"\x30\x0b\x02\x01\x00\x30\x00\x30\x02\x05\x00\xa0\x00";
        let xml: String = build_request(
            "https://ces.corp.example.org/CORP-CA_CES_Kerberos/service.svc/CES",
            "urn:uuid:5f0d2a5e-8a3c-4c41-9b0e-2f1d6c7a9e10",
            csr,
        )
        .expect("envelope");
        // The golden file is one line, so a CRLF checkout cannot alter it
        // beyond the trailing newline trimmed here.
        assert_eq!(xml, include_str!("request.golden.xml").trim_end());
    }

    #[test]
    fn endpoint_is_escaped_as_text() {
        let xml: String = build_request(
            "https://ces.corp.example.org/CES?a=1&b=<2>",
            "urn:uuid:x",
            b"\x30\x00",
        )
        .expect("envelope");
        assert!(xml.contains("<a:To>https://ces.corp.example.org/CES?a=1&amp;b=&lt;2&gt;</a:To>"));
    }

    #[test]
    fn message_ids_are_unique_v4_urns() {
        let first: String = new_message_id();
        let second: String = new_message_id();
        assert_ne!(first, second);
        let parsed: uuid::Uuid =
            uuid::Uuid::parse_str(first.strip_prefix("urn:uuid:").expect("urn:uuid: prefix"))
                .expect("uuid");
        assert_eq!(parsed.get_version_num(), 4);
    }

    #[test]
    fn envelope_round_trips_through_the_reader_with_its_namespaces() {
        use quick_xml::events::Event;
        use quick_xml::name::{Namespace, ResolveResult};
        use quick_xml::NsReader;

        let xml: String = build_request(
            "https://ces.corp.example.org/CES",
            "urn:uuid:x",
            b"\x30\x00",
        )
        .expect("envelope");
        let mut reader: NsReader<&[u8]> = NsReader::from_str(&xml);
        let mut seen: Vec<(String, String)> = Vec::new();
        loop {
            match reader.read_resolved_event().expect("well-formed") {
                (ResolveResult::Bound(Namespace(ns)), Event::Start(e) | Event::Empty(e)) => {
                    seen.push((ns.to_owned(), e.local_name().as_ref().to_owned()));
                }
                (_, Event::Eof) => break,
                _ => {}
            }
        }
        for (ns, local) in [
            (SOAP_ENVELOPE_NS, "Envelope"),
            (WS_ADDRESSING_NS, "Action"),
            (WS_ADDRESSING_NS, "MessageID"),
            (WS_ADDRESSING_NS, "To"),
            (WS_TRUST_NS, "RequestSecurityToken"),
            (WS_TRUST_NS, "TokenType"),
            (WSSE_NS, "BinarySecurityToken"),
            (ENROLLMENT_NS, "RequestID"),
        ] {
            assert!(
                seen.contains(&(ns.to_owned(), local.to_owned())),
                "{{{ns}}}{local} missing"
            );
        }
        assert!(!seen.iter().any(|(_, local)| local == "Security"));
    }
}
