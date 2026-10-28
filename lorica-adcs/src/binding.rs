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

//! The `tls-server-end-point` channel binding of RFC 5929, which IIS
//! Extended Protection requires in the SPNEGO token (Epic 13 D2).

use ring::digest;
use x509_parser::certificate::X509Certificate;

use crate::AdcsError;

/// The prefix RFC 5929 4.1 puts before the certificate hash.
const BINDING_PREFIX: &[u8] = b"tls-server-end-point:";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BindingHash {
    Sha256,
    Sha384,
    Sha512,
}

impl BindingHash {
    fn algorithm(self) -> &'static digest::Algorithm {
        match self {
            BindingHash::Sha256 => &digest::SHA256,
            BindingHash::Sha384 => &digest::SHA384,
            BindingHash::Sha512 => &digest::SHA512,
        }
    }
}

/// Signature algorithms whose hash RFC 5929 4.1 makes usable, keyed by
/// dotted OID. Only RSA PKCS#1 v1.5 and ECDSA are listed: they name one
/// hash in the OID itself. RSASSA-PSS carries its hash in parameters
/// whose handling by Windows is unconfirmed, and EdDSA has no separate
/// hash at all, so both are refused rather than guessed (Epic 13 D2).
const BINDING_HASHES: &[(&str, BindingHash)] = &[
    // MD5 and SHA-1 are replaced by SHA-256 (RFC 5929 4.1).
    ("1.2.840.113549.1.1.4", BindingHash::Sha256), // md5WithRSAEncryption
    ("1.2.840.113549.1.1.5", BindingHash::Sha256), // sha1WithRSAEncryption
    ("1.3.14.3.2.29", BindingHash::Sha256),        // sha1WithRSASignature (OIW)
    ("1.2.840.10045.4.1", BindingHash::Sha256),    // ecdsa-with-SHA1
    ("1.2.840.113549.1.1.11", BindingHash::Sha256), // sha256WithRSAEncryption
    ("1.2.840.113549.1.1.12", BindingHash::Sha384), // sha384WithRSAEncryption
    ("1.2.840.113549.1.1.13", BindingHash::Sha512), // sha512WithRSAEncryption
    ("1.2.840.10045.4.3.2", BindingHash::Sha256),  // ecdsa-with-SHA256
    ("1.2.840.10045.4.3.3", BindingHash::Sha384),  // ecdsa-with-SHA384
    ("1.2.840.10045.4.3.4", BindingHash::Sha512),  // ecdsa-with-SHA512
];

fn binding_hash_for(signature_oid: &str) -> Option<BindingHash> {
    BINDING_HASHES
        .iter()
        .find(|(oid, _)| *oid == signature_oid)
        .map(|(_, hash)| *hash)
}

/// The `tls-server-end-point` channel binding data of RFC 5929 for the
/// server certificate `cert_der`: the ASCII prefix
/// `tls-server-end-point:` followed by the certificate's hash.
///
/// The hash is the one of the certificate's signature algorithm, with
/// MD5 and SHA-1 replaced by SHA-256. A certificate whose signature has
/// no such hash (RSASSA-PSS, EdDSA, an unknown OID) is refused with its
/// OID in the error, never bound with a guessed hash: a wrong binding is
/// a 401 that would look like a Kerberos failure.
pub(crate) fn channel_binding(cert_der: &[u8]) -> Result<Vec<u8>, AdcsError> {
    let (_, cert): (&[u8], X509Certificate<'_>) = x509_parser::parse_x509_certificate(cert_der)
        .map_err(|err| AdcsError::ChannelBindingCertificate {
            reason: err.to_string(),
        })?;
    let signature_oid: String = cert.signature_algorithm.algorithm.to_id_string();
    let hash: BindingHash = binding_hash_for(&signature_oid)
        .ok_or(AdcsError::ChannelBindingAlgorithm { oid: signature_oid })?;
    let certificate_digest: digest::Digest = digest::digest(hash.algorithm(), cert_der);
    let mut binding: Vec<u8> =
        Vec::with_capacity(BINDING_PREFIX.len() + certificate_digest.as_ref().len());
    binding.extend_from_slice(BINDING_PREFIX);
    binding.extend_from_slice(certificate_digest.as_ref());
    Ok(binding)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::der::{tlv, TAG_SEQUENCE};
    use crate::test_support::{der_split, oid_der};
    use rcgen::{
        CertificateParams, KeyPair, PKCS_ECDSA_P256_SHA256, PKCS_ECDSA_P384_SHA384, PKCS_ED25519,
    };

    fn generated_cert(alg: &'static rcgen::SignatureAlgorithm) -> Vec<u8> {
        let key: KeyPair = KeyPair::generate_for(alg).expect("generate key");
        let params: CertificateParams =
            CertificateParams::new(vec!["ces.corp.example.org".to_owned()]).expect("params");
        params.self_signed(&key).expect("self-sign").der().to_vec()
    }

    /// A copy of `cert_der` whose outer `signatureAlgorithm` names
    /// `oid`, with NULL parameters when `null_params`. rcgen cannot sign
    /// with MD5 or SHA-1, and the binding reads the OID only, so those
    /// families (and unknown OIDs) are exercised on a certificate
    /// re-labelled this way rather than truly signed.
    fn relabelled(cert_der: &[u8], oid: &str, null_params: bool) -> Vec<u8> {
        let outer: Vec<&[u8]> = der_split(cert_der);
        let tbs: &[u8] = outer[0];
        let signature: &[u8] = outer[2];
        let mut alg_content: Vec<u8> = oid_der(oid);
        if null_params {
            alg_content.extend_from_slice(&[0x05, 0x00]);
        }
        let mut content: Vec<u8> = tbs.to_vec();
        content.extend_from_slice(&tlv(TAG_SEQUENCE, &alg_content));
        content.extend_from_slice(signature);
        tlv(TAG_SEQUENCE, &content)
    }

    fn assert_binding(cert_der: &[u8], expected: &'static digest::Algorithm) {
        let binding: Vec<u8> = channel_binding(cert_der).expect("binding");
        let mut want: Vec<u8> = b"tls-server-end-point:".to_vec();
        want.extend_from_slice(digest::digest(expected, cert_der).as_ref());
        assert_eq!(binding, want);
    }

    #[test]
    fn ecdsa_p256_sha256_certificate_binds_with_sha256() {
        let cert: Vec<u8> = generated_cert(&PKCS_ECDSA_P256_SHA256);
        assert_binding(&cert, &digest::SHA256);
    }

    #[test]
    fn ecdsa_p384_sha384_certificate_binds_with_sha384() {
        let cert: Vec<u8> = generated_cert(&PKCS_ECDSA_P384_SHA384);
        assert_binding(&cert, &digest::SHA384);
    }

    #[test]
    fn ecdsa_sha1_and_sha512_follow_rfc_5929() {
        let base: Vec<u8> = generated_cert(&PKCS_ECDSA_P256_SHA256);
        assert_binding(
            &relabelled(&base, "1.2.840.10045.4.1", false),
            &digest::SHA256,
        );
        assert_binding(
            &relabelled(&base, "1.2.840.10045.4.3.4", false),
            &digest::SHA512,
        );
    }

    #[test]
    fn rsa_pkcs1_md5_and_sha1_are_upgraded_to_sha256() {
        let base: Vec<u8> = generated_cert(&PKCS_ECDSA_P256_SHA256);
        for oid in [
            "1.2.840.113549.1.1.4",
            "1.2.840.113549.1.1.5",
            "1.3.14.3.2.29",
        ] {
            assert_binding(&relabelled(&base, oid, true), &digest::SHA256);
        }
    }

    #[test]
    fn rsa_pkcs1_sha2_family_uses_the_signature_hash() {
        let base: Vec<u8> = generated_cert(&PKCS_ECDSA_P256_SHA256);
        assert_binding(
            &relabelled(&base, "1.2.840.113549.1.1.11", true),
            &digest::SHA256,
        );
        assert_binding(
            &relabelled(&base, "1.2.840.113549.1.1.12", true),
            &digest::SHA384,
        );
        // The spike's CES certificate was SHA-512 RSA: a SHA-256 binding
        // was refused there.
        assert_binding(
            &relabelled(&base, "1.2.840.113549.1.1.13", true),
            &digest::SHA512,
        );
    }

    // The spike's CES certificate was RSA with SHA-512; IV2 asks for
    // SHA-512 and SHA-256 server certificates to bind.
    #[test]
    fn truly_signed_rsa_and_p521_certificates_bind_with_their_signature_hash() {
        let rsa = |alg: &'static rcgen::SignatureAlgorithm| {
            KeyPair::generate_rsa_for(alg, rcgen::RsaKeySize::_2048).expect("generate rsa key")
        };
        let cases: [(KeyPair, &'static digest::Algorithm); 4] = [
            (rsa(&rcgen::PKCS_RSA_SHA256), &digest::SHA256),
            (rsa(&rcgen::PKCS_RSA_SHA384), &digest::SHA384),
            (rsa(&rcgen::PKCS_RSA_SHA512), &digest::SHA512),
            (
                KeyPair::generate_for(&rcgen::PKCS_ECDSA_P521_SHA512).expect("generate p521 key"),
                &digest::SHA512,
            ),
        ];
        for (key, hash) in cases {
            let params: CertificateParams =
                CertificateParams::new(vec!["ces.corp.example.org".to_owned()]).expect("params");
            let cert: Vec<u8> = params.self_signed(&key).expect("self-sign").der().to_vec();
            assert_binding(&cert, hash);
        }
    }

    #[test]
    fn every_listed_oid_dispatches_end_to_end() {
        let base: Vec<u8> = generated_cert(&PKCS_ECDSA_P256_SHA256);
        for (oid, hash) in BINDING_HASHES {
            assert_binding(&relabelled(&base, oid, true), hash.algorithm());
        }
    }

    #[test]
    fn unsupported_algorithms_are_refused_with_their_oid() {
        let ed25519: Vec<u8> = generated_cert(&PKCS_ED25519);
        let base: Vec<u8> = generated_cert(&PKCS_ECDSA_P256_SHA256);
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (ed25519, "1.3.101.112"),
            (relabelled(&base, "1.3.101.113", false), "1.3.101.113"),
            (
                relabelled(&base, "1.2.840.113549.1.1.10", false),
                "1.2.840.113549.1.1.10",
            ),
            (
                relabelled(&base, "1.2.840.113549.1.1.14", true),
                "1.2.840.113549.1.1.14",
            ),
            (relabelled(&base, "1.2.3.4.5", false), "1.2.3.4.5"),
        ];
        for (cert, oid) in cases {
            let err: AdcsError = channel_binding(&cert).expect_err("must be refused");
            assert!(
                matches!(&err, AdcsError::ChannelBindingAlgorithm { oid: got } if got == oid),
                "{err}"
            );
            assert!(err.to_string().contains(oid), "{err}");
        }
    }

    #[test]
    fn garbage_is_a_certificate_error_not_a_panic() {
        let err: AdcsError = channel_binding(b"not a certificate").expect_err("refused");
        assert!(matches!(err, AdcsError::ChannelBindingCertificate { .. }));
    }
}
