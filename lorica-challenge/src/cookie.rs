// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Verdict cookie sign / verify.
//!
//! Wire format (binary, pre-encoding):
//!
//! ```text
//! payload  = route_id (16 B UUID)
//!         || ip_disc (1 B: 1=v4, 2=v6)
//!         || ip_bytes (3 B for v4 /24, 8 B for v6 /64)
//!         || expires_at (4 B u32 LE, seconds since UNIX epoch)
//!         || mode (1 B: 1=Cookie, 2=Javascript, 3=Captcha)
//! tag      = first 16 bytes of HMAC-SHA256(secret, payload)
//! cookie   = base64_url_nopad(payload || tag)
//! ```
//!
//! Fixed wire sizes (including the tag):
//! - v4 client: 16 + 1 + 3 + 4 + 1 + 16 = **41 bytes**  (~55 base64 chars)
//! - v6 client: 16 + 1 + 8 + 4 + 1 + 16 = **46 bytes**  (~62 base64 chars)
//!
//! The `ip_disc` discriminator is redundant with the payload length
//! but avoids relying on length arithmetic in the parser — a future
//! protocol tweak (e.g. adding nonce bytes) would otherwise shift
//! every field.
//!
//! ## Security properties
//!
//! - **Integrity.** HMAC-SHA256 with a 32-byte secret. Tag
//!   truncated to 128 bits, which is the standard "enough against
//!   collision search" length for authenticated tokens.
//! - **Confidentiality.** None — the payload is plaintext. This is
//!   intentional: the payload contains nothing secret (route_id
//!   is already in the response headers, IP prefix is public,
//!   expires_at is trivial, mode is a UX signal). Encrypting adds
//!   complexity without adding defence.
//! - **Constant-time verify.** [`verify`] uses
//!   `subtle::ConstantTimeEq::ct_eq` so an attacker with timing
//!   access cannot mount a byte-wise forgery attack against the
//!   tag. `==` on byte slices short-circuits on the first diff
//!   and would leak the tag one byte at a time.
//! - **Clock-skew tolerance.** The verifier accepts cookies whose
//!   `expires_at` is up to 30 seconds in the past, so a client
//!   with a drifting clock does not lose its cookie mid-session.

use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use subtle::ConstantTimeEq;

use crate::{ChallengeError, IpPrefix, Mode, Result};

/// Maximum clock skew (seconds) accepted between Lorica and the
/// client-reported browser clock. 30 s matches the NTP minor-
/// adjustment window; anything looser opens the cookie to replay
/// across a longer stealing window than `cookie_ttl_s` advertises.
const CLOCK_SKEW_GRACE_S: i64 = 30;

/// Length of the truncated HMAC tag, in bytes. 128 bits = standard
/// authenticator strength; truncating full 256-bit SHA-256 is
/// safe per RFC 2104 § 5.
const TAG_LEN: usize = 16;

/// Length of the fixed-shape prefix of the payload (everything up
/// to and including the IP-prefix discriminator).
///   16 B route_id + 1 B ip_disc = 17 B
const PAYLOAD_PREFIX_LEN: usize = 16 + 1;

/// Length of the fixed-shape suffix of the payload (after the
/// variable-length IP prefix).
///   4 B expires_at + 1 B mode = 5 B
const PAYLOAD_SUFFIX_LEN: usize = 4 + 1;

/// All the context needed to mint or verify one verdict cookie.
/// Captured into a struct so the public API does not grow five
/// positional arguments.
#[derive(Debug, Clone)]
pub struct Payload {
    pub route_id: [u8; 16],
    pub ip_prefix: IpPrefix,
    pub expires_at: i64,
    pub mode: Mode,
}

/// Serialise a payload into its fixed binary shape. Used by
/// [`sign`] and by tests; exposed in case callers need to compute
/// the HMAC manually (e.g. a future multi-region Lorica that
/// cross-signs cookies).
pub fn encode_payload(p: &Payload) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        PAYLOAD_PREFIX_LEN + p.ip_prefix.as_bytes().len() + PAYLOAD_SUFFIX_LEN,
    );
    out.extend_from_slice(&p.route_id);
    out.push(p.ip_prefix.discriminator());
    out.extend_from_slice(p.ip_prefix.as_bytes());
    // expires_at fits in u32 until 2106; stored little-endian for
    // consistency with the rest of the Lorica SQLite wire format.
    debug_assert!(
        p.expires_at >= 0 && p.expires_at <= u32::MAX as i64,
        "expires_at {0} does not fit in u32 (negative or past 2106)",
        p.expires_at
    );
    let exp_u32 = p.expires_at.clamp(0, u32::MAX as i64) as u32;
    out.extend_from_slice(&exp_u32.to_le_bytes());
    out.push(p.mode as u8);
    out
}

/// Mint a verdict cookie. Returns the base64url string that goes
/// into the `Set-Cookie` header value.
pub fn sign(p: &Payload, secret: &[u8; 32]) -> String {
    let payload = encode_payload(p);
    let tag = hmac_tag(secret, &payload);
    let mut wire = payload;
    wire.extend_from_slice(&tag);
    URL_SAFE_NO_PAD.encode(&wire)
}

/// Verify a verdict cookie. Returns the decoded payload on
/// success; `ChallengeError::*` on any failure.
///
/// `now` is the current UNIX timestamp (seconds). Passed as a
/// parameter rather than read from `SystemTime` so tests can pin
/// the clock and so a future callsite inside a deterministic
/// replayer can reproduce past verdicts.
pub fn verify(cookie: &str, secret: &[u8; 32], now: i64) -> Result<Payload> {
    let wire = URL_SAFE_NO_PAD
        .decode(cookie.as_bytes())
        .map_err(|_| ChallengeError::Malformed("cookie is not valid base64url"))?;

    if wire.len() < PAYLOAD_PREFIX_LEN + PAYLOAD_SUFFIX_LEN + TAG_LEN {
        return Err(ChallengeError::Malformed("cookie too short"));
    }

    let ip_disc = wire[16];
    let ip_bytes_len = match ip_disc {
        1 => 3,
        2 => 8,
        _ => {
            return Err(ChallengeError::Malformed(
                "cookie IP discriminator neither 1 (v4) nor 2 (v6)",
            ))
        }
    };
    let expected_len =
        PAYLOAD_PREFIX_LEN + ip_bytes_len + PAYLOAD_SUFFIX_LEN + TAG_LEN;
    if wire.len() != expected_len {
        return Err(ChallengeError::Malformed(
            "cookie length does not match IP discriminator",
        ));
    }

    let payload_end = wire.len() - TAG_LEN;
    let payload = &wire[..payload_end];
    let tag = &wire[payload_end..];

    // Constant-time tag verification.
    let expected = hmac_tag(secret, payload);
    if expected.ct_eq(tag).unwrap_u8() != 1 {
        return Err(ChallengeError::BadSignature);
    }

    // Parse the known-valid payload. Offsets are fixed modulo the
    // ip_bytes_len known above.
    let mut route_id = [0u8; 16];
    route_id.copy_from_slice(&payload[..16]);

    let ip_start = PAYLOAD_PREFIX_LEN;
    let ip_end = ip_start + ip_bytes_len;
    let ip_prefix = match ip_disc {
        1 => {
            let mut b = [0u8; 4];
            b[..3].copy_from_slice(&payload[ip_start..ip_end]);
            IpPrefix::V4(b)
        }
        2 => {
            let mut b = [0u8; 16];
            b[..8].copy_from_slice(&payload[ip_start..ip_end]);
            IpPrefix::V6(b)
        }
        _ => unreachable!("checked above"),
    };

    let exp_bytes: [u8; 4] = payload[ip_end..ip_end + 4]
        .try_into()
        .map_err(|_| ChallengeError::Malformed("cookie expires_at slice mismatch"))?;
    let expires_at = u32::from_le_bytes(exp_bytes) as i64;

    let mode = Mode::from_u8(payload[ip_end + 4])
        .ok_or(ChallengeError::Malformed("cookie mode byte invalid"))?;

    if now - CLOCK_SKEW_GRACE_S > expires_at {
        return Err(ChallengeError::Expired {
            reason: "cookie expires_at in the past",
        });
    }

    Ok(Payload {
        route_id,
        ip_prefix,
        expires_at,
        mode,
    })
}

/// Compute the truncated HMAC-SHA256 tag over `bytes`. Returns the
/// first [`TAG_LEN`] bytes of the full 32-byte MAC. Kept module-
/// private because the truncation length and the tag shape are
/// invariants of the wire format, not knobs.
fn hmac_tag(secret: &[u8; 32], bytes: &[u8]) -> [u8; TAG_LEN] {
    // HMAC-SHA256 supports variable-length keys via a one-time
    // hashing of oversized keys; for our 32-byte key this is a
    // direct copy into the inner / outer pad. Panic surface:
    // `Hmac::new_from_slice` only errors on key length issues,
    // which is impossible here since the key type is fixed-size.
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(secret)
        .expect("HMAC-SHA256 accepts any key length");
    mac.update(bytes);
    let full = mac.finalize().into_bytes();
    let mut out = [0u8; TAG_LEN];
    out.copy_from_slice(&full[..TAG_LEN]);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn test_secret() -> [u8; 32] {
        let mut s = [0u8; 32];
        for (i, b) in s.iter_mut().enumerate() {
            *b = i as u8;
        }
        s
    }

    fn test_payload_v4() -> Payload {
        Payload {
            route_id: [0xAAu8; 16],
            ip_prefix: IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42))),
            expires_at: 2_000_000_000, // 2033-ish
            mode: Mode::Javascript,
        }
    }

    fn test_payload_v6() -> Payload {
        Payload {
            route_id: [0xBBu8; 16],
            ip_prefix: IpPrefix::from_ip(IpAddr::V6(Ipv6Addr::new(
                0x2001, 0x0db8, 0, 0, 0, 0, 0, 1,
            ))),
            expires_at: 2_000_000_000,
            mode: Mode::Captcha,
        }
    }

    #[test]
    fn sign_and_verify_v4_roundtrip() {
        let secret = test_secret();
        let p = test_payload_v4();
        let cookie = sign(&p, &secret);
        let got = verify(&cookie, &secret, 1_900_000_000).expect("fresh cookie must verify");
        assert_eq!(got.route_id, p.route_id);
        assert_eq!(got.ip_prefix, p.ip_prefix);
        assert_eq!(got.expires_at, p.expires_at);
        assert_eq!(got.mode, p.mode);
    }

    #[test]
    fn sign_and_verify_v6_roundtrip() {
        let secret = test_secret();
        let p = test_payload_v6();
        let cookie = sign(&p, &secret);
        let got = verify(&cookie, &secret, 1_900_000_000).expect("fresh cookie must verify");
        assert_eq!(got.ip_prefix, p.ip_prefix);
        assert_eq!(got.mode, p.mode);
    }

    #[test]
    fn verify_rejects_bad_base64() {
        let secret = test_secret();
        let err = verify("not@@@base64", &secret, 0).unwrap_err();
        assert!(matches!(err, ChallengeError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn verify_rejects_truncated_cookie() {
        let secret = test_secret();
        let cookie = sign(&test_payload_v4(), &secret);
        // Lop off the last 2 chars of the base64 string, which
        // removes ~10 bits of the tag. Shape check must fire before
        // the HMAC check.
        let truncated = &cookie[..cookie.len() - 2];
        let err = verify(truncated, &secret, 0).unwrap_err();
        assert!(matches!(err, ChallengeError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn verify_rejects_flipped_payload_byte() {
        let secret = test_secret();
        let cookie = sign(&test_payload_v4(), &secret);
        let mut wire = URL_SAFE_NO_PAD.decode(&cookie).unwrap();
        // Flip one bit of the route_id. HMAC tag should no longer match.
        wire[0] ^= 0x01;
        let tampered = URL_SAFE_NO_PAD.encode(&wire);
        let err = verify(&tampered, &secret, 1_900_000_000).unwrap_err();
        assert!(matches!(err, ChallengeError::BadSignature), "{err:?}");
    }

    #[test]
    fn verify_rejects_flipped_tag_byte() {
        let secret = test_secret();
        let cookie = sign(&test_payload_v4(), &secret);
        let mut wire = URL_SAFE_NO_PAD.decode(&cookie).unwrap();
        let last = wire.len() - 1;
        wire[last] ^= 0x80;
        let tampered = URL_SAFE_NO_PAD.encode(&wire);
        let err = verify(&tampered, &secret, 1_900_000_000).unwrap_err();
        assert!(matches!(err, ChallengeError::BadSignature), "{err:?}");
    }

    #[test]
    fn verify_rejects_wrong_secret() {
        let secret = test_secret();
        let cookie = sign(&test_payload_v4(), &secret);
        let other = [0xFFu8; 32];
        let err = verify(&cookie, &other, 1_900_000_000).unwrap_err();
        assert!(matches!(err, ChallengeError::BadSignature), "{err:?}");
    }

    #[test]
    fn verify_rejects_expired_cookie() {
        let secret = test_secret();
        let p = Payload {
            expires_at: 1_000_000_000,
            ..test_payload_v4()
        };
        let cookie = sign(&p, &secret);
        // now = 1h past expiry, well beyond the 30s skew grace.
        let err = verify(&cookie, &secret, 1_000_003_600).unwrap_err();
        assert!(matches!(err, ChallengeError::Expired { .. }), "{err:?}");
    }

    #[test]
    fn verify_accepts_within_skew_grace() {
        let secret = test_secret();
        let p = Payload {
            expires_at: 1_000_000_000,
            ..test_payload_v4()
        };
        let cookie = sign(&p, &secret);
        // now = 10s past expiry, inside the 30s grace.
        let ok = verify(&cookie, &secret, 1_000_000_010).expect("within skew");
        assert_eq!(ok.expires_at, 1_000_000_000);
    }

    #[test]
    fn verify_rejects_invalid_ip_discriminator() {
        let secret = test_secret();
        let cookie = sign(&test_payload_v4(), &secret);
        let mut wire = URL_SAFE_NO_PAD.decode(&cookie).unwrap();
        wire[16] = 9; // neither 1 nor 2
        let tampered = URL_SAFE_NO_PAD.encode(&wire);
        let err = verify(&tampered, &secret, 1_900_000_000).unwrap_err();
        assert!(matches!(err, ChallengeError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn cookie_size_v4_is_deterministic() {
        // Document the wire-size guarantee: 41 raw bytes before
        // base64url, which rounds up to 55 chars (no padding).
        let cookie = sign(&test_payload_v4(), &test_secret());
        assert_eq!(cookie.len(), 55, "expected 55 chars, got '{cookie}'");
    }

    #[test]
    fn cookie_size_v6_is_deterministic() {
        // 46 raw bytes → 62 base64url chars (no padding).
        let cookie = sign(&test_payload_v6(), &test_secret());
        assert_eq!(cookie.len(), 62, "expected 62 chars, got '{cookie}'");
    }

    #[test]
    fn different_ip_same_slash24_validates_same_cookie() {
        // Documents the NAT-tolerance design intent: a cookie
        // minted for 192.0.2.42 also validates at verify time
        // against 192.0.2.99 because the HMAC payload only
        // captures the /24 prefix.
        let secret = test_secret();
        let p = Payload {
            ip_prefix: IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 42))),
            ..test_payload_v4()
        };
        let cookie = sign(&p, &secret);
        let got = verify(&cookie, &secret, 1_900_000_000).unwrap();
        // Caller will separately compare got.ip_prefix with
        // IpPrefix::from_ip(new_client_ip) — they must be equal.
        assert_eq!(
            got.ip_prefix,
            IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::new(192, 0, 2, 99)))
        );
    }
}
