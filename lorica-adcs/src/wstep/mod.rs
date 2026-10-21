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

//! The WS-Trust X.509v3 enrollment exchange of MS-WSTEP: the one
//! request shape Lorica sends and the response shapes it reads.
//!
//! The URIs are copied from the request and response examples of
//! MS-WSTEP 4.1.1.1 and 4.1.1.2 (v20240423), not retyped from the
//! schemas: the `EncodingType` keeps its lower-case `b` and the request's
//! `ValueType` says `#PKCS7` although the payload is a bare PKCS#10,
//! because that is what the specification's own client sends.

pub mod request;
pub mod response;

/// SOAP 1.2.
pub(crate) const SOAP_ENVELOPE_NS: &str = "http://www.w3.org/2003/05/soap-envelope";
/// WS-Addressing 1.0.
pub(crate) const WS_ADDRESSING_NS: &str = "http://www.w3.org/2005/08/addressing";
/// WS-Trust 1.3.
pub(crate) const WS_TRUST_NS: &str = "http://docs.oasis-open.org/ws-sx/ws-trust/200512";
/// WS-Security 1.0 secext, the namespace of `BinarySecurityToken`.
pub(crate) const WSSE_NS: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
/// The MS-WSTEP enrollment extensions (`RequestID`, `DispositionMessage`,
/// `CertificateEnrollmentWSDetail`).
pub(crate) const ENROLLMENT_NS: &str =
    "http://schemas.microsoft.com/windows/pki/2009/01/enrollment";
/// XML Schema instance, for `xsi:nil`.
pub(crate) const XSI_NS: &str = "http://www.w3.org/2001/XMLSchema-instance";

/// The WS-Addressing action of an enrollment request.
pub(crate) const RST_ACTION: &str =
    "http://schemas.microsoft.com/windows/pki/2009/01/enrollment/RST/wstep";
/// The anonymous `ReplyTo` address: the response comes back on the
/// same HTTP exchange.
pub(crate) const ANONYMOUS_ADDRESS: &str = "http://www.w3.org/2005/08/addressing/anonymous";
/// The token type requested, and the `ValueType` of the issued leaf.
pub(crate) const X509V3_VALUE_TYPE: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-x509-token-profile-1.0#X509v3";
/// `RequestType` Issue.
pub(crate) const ISSUE_REQUEST_TYPE: &str =
    "http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue";
/// `EncodingType` of every `BinarySecurityToken`.
pub(crate) const BASE64_ENCODING_TYPE: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#base64binary";
/// `ValueType` of the request's CSR and of the response's CMC chain.
pub(crate) const PKCS7_VALUE_TYPE: &str =
    "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd#PKCS7";
