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

//! Join tokens (Story 9.3 AC #1/#2): shape, minting, parsing and the
//! keyed verification.
//!
//! # Shape
//!
//! `<public_id>.<payload>` where `public_id` is 12 random bytes as
//! lowercase hex (the indexed lookup key, so a redemption is ONE
//! lookup and ONE verification) and `payload` is the URL-safe base64
//! (no padding) of `secret[32] || control_plane_leaf_spki_sha256[32]`.
//! The pin rides inside the token so the joiner can authenticate the
//! control plane before it has any CA (AC #2: the LEAF key is pinned,
//! never the CA - pinning the CA would admit any certificate the
//! cluster CA ever issued, i.e. a compromised follower posing as the
//! control plane).
//!
//! # Verification
//!
//! The database stores HMAC-SHA256(server_key, secret) as hex. The
//! secret is 256 bits of machine entropy, not a human password, so a
//! memory-hard KDF buys nothing and would turn the enrollment path
//! into a memory-exhaustion primitive (19 MiB per argon2id verify).
//! [`verify_secret`] is constant-time (`ring::hmac::verify`) and the
//! redemption handler runs it against a fixed dummy digest when the
//! `public_id` is unknown, so timing and error are identical either
//! way.

use ring::hmac;
use ring::rand::{SecureRandom, SystemRandom};

/// Bytes in the public (lookup) half.
pub const PUBLIC_ID_LEN: usize = 12;
/// Bytes in the secret half.
pub const SECRET_LEN: usize = 32;
/// Bytes in the SPKI pin.
pub const PIN_LEN: usize = 32;

/// Why a token string could not be parsed. Deliberately shapeless
/// (one variant): a joiner with a mistyped token gets one message,
/// the enrollment path never echoes any of it.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
#[error("malformed join token")]
pub struct TokenFormatError;

/// A freshly minted token: what the operator sees ONCE, and what the
/// registry stores.
#[derive(Debug)]
pub struct MintedToken {
    /// The full `<public_id>.<payload>` string; shown once, never
    /// stored, never logged.
    pub token: String,
    /// The lookup half, stored in clear.
    pub public_id: String,
    /// Lowercase-hex HMAC-SHA256 of the secret half under the server
    /// key; the only thing the registry keeps of the secret.
    pub secret_hmac: String,
}

/// A parsed token, on the joining side or the redeeming side.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedToken {
    /// The lookup half.
    pub public_id: String,
    /// The secret half.
    pub secret: [u8; SECRET_LEN],
    /// SHA-256 of the control-plane leaf SPKI the joiner must see.
    pub pin: [u8; PIN_LEN],
}

/// Mint a token pinning `leaf_spki_sha256` (the control plane's
/// current leaf SPKI digest) and hash its secret under `hmac_key`.
pub fn mint(hmac_key: &[u8], leaf_spki_sha256: &[u8; PIN_LEN]) -> Result<MintedToken, String> {
    let rng = SystemRandom::new();
    let mut public = [0u8; PUBLIC_ID_LEN];
    let mut secret = [0u8; SECRET_LEN];
    rng.fill(&mut public)
        .map_err(|_| "token randomness unavailable".to_string())?;
    rng.fill(&mut secret)
        .map_err(|_| "token randomness unavailable".to_string())?;
    let public_id = hex(&public);
    let mut payload = Vec::with_capacity(SECRET_LEN + PIN_LEN);
    payload.extend_from_slice(&secret);
    payload.extend_from_slice(leaf_spki_sha256);
    let token = format!("{public_id}.{}", base64url_encode(&payload));
    Ok(MintedToken {
        token,
        public_id,
        secret_hmac: secret_hmac_hex(hmac_key, &secret),
    })
}

/// Parse a token string. Surrounding whitespace is tolerated (tokens
/// arrive through files and stdin).
pub fn parse(token: &str) -> Result<ParsedToken, TokenFormatError> {
    let token = token.trim();
    let (public_id, payload) = token.split_once('.').ok_or(TokenFormatError)?;
    if public_id.len() != PUBLIC_ID_LEN * 2
        || !public_id.bytes().all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
    {
        return Err(TokenFormatError);
    }
    let bytes = base64url_decode(payload).ok_or(TokenFormatError)?;
    if bytes.len() != SECRET_LEN + PIN_LEN {
        return Err(TokenFormatError);
    }
    let mut secret = [0u8; SECRET_LEN];
    let mut pin = [0u8; PIN_LEN];
    secret.copy_from_slice(&bytes[..SECRET_LEN]);
    pin.copy_from_slice(&bytes[SECRET_LEN..]);
    Ok(ParsedToken {
        public_id: public_id.to_string(),
        secret,
        pin,
    })
}

/// Lowercase-hex HMAC-SHA256 of `secret` under `hmac_key`.
pub fn secret_hmac_hex(hmac_key: &[u8], secret: &[u8]) -> String {
    let key = hmac::Key::new(hmac::HMAC_SHA256, hmac_key);
    hex(hmac::sign(&key, secret).as_ref())
}

/// Constant-time check of `secret` against a stored hex digest. A
/// digest that is not valid hex verifies as false in the same time.
pub fn verify_secret(hmac_key: &[u8], secret: &[u8], stored_hmac_hex: &str) -> bool {
    let key = hmac::Key::new(hmac::HMAC_SHA256, hmac_key);
    let expected = unhex(stored_hmac_hex).unwrap_or_else(|| vec![0u8; 32]);
    hmac::verify(&key, secret, &expected).is_ok()
}

/// A stored digest to verify against when the `public_id` is unknown,
/// so the unknown-id path costs exactly one verification like the
/// known-id path.
pub fn dummy_secret_hmac_hex() -> String {
    hex(&[0u8; 32])
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn unhex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

/// URL-safe base64 without padding (RFC 4648 section 5). Kept local:
/// it keeps `base64` out of the crate and the alphabet is fixed by
/// the token format, not by a library default.
fn base64url_encode(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0];
        let b1 = chunk.get(1).copied().unwrap_or(0);
        let b2 = chunk.get(2).copied().unwrap_or(0);
        out.push(B64[(b0 >> 2) as usize] as char);
        out.push(B64[(((b0 & 0x03) << 4) | (b1 >> 4)) as usize] as char);
        if chunk.len() > 1 {
            out.push(B64[(((b1 & 0x0f) << 2) | (b2 >> 6)) as usize] as char);
        }
        if chunk.len() > 2 {
            out.push(B64[(b2 & 0x3f) as usize] as char);
        }
    }
    out
}

fn base64url_decode(s: &str) -> Option<Vec<u8>> {
    fn value(c: u8) -> Option<u8> {
        B64.iter().position(|&b| b == c).map(|p| p as u8)
    }
    if s.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(s.len() * 3 / 4);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(4) {
        let mut vals = [0u8; 4];
        for (i, &c) in chunk.iter().enumerate() {
            vals[i] = value(c)?;
        }
        out.push((vals[0] << 2) | (vals[1] >> 4));
        if chunk.len() > 2 {
            out.push((vals[1] << 4) | (vals[2] >> 2));
        }
        if chunk.len() > 3 {
            out.push((vals[2] << 6) | vals[3]);
        }
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mint_then_parse_round_trips_every_part() {
        let key = [7u8; 32];
        let pin = [0xabu8; PIN_LEN];
        let minted = mint(&key, &pin).expect("mint");
        let parsed = parse(&format!("  {}\n", minted.token)).expect("parse");
        assert_eq!(parsed.public_id, minted.public_id);
        assert_eq!(parsed.pin, pin);
        assert!(verify_secret(&key, &parsed.secret, &minted.secret_hmac));
        assert!(!verify_secret(&[8u8; 32], &parsed.secret, &minted.secret_hmac));
        assert!(!verify_secret(&key, &[0u8; SECRET_LEN], &minted.secret_hmac));
        assert!(!verify_secret(&key, &parsed.secret, &dummy_secret_hmac_hex()));
        assert!(!verify_secret(&key, &parsed.secret, "not hex"));
        // The token never contains the secret's HMAC or padding.
        assert!(!minted.token.contains(&minted.secret_hmac));
        assert!(!minted.token.contains('='));
    }

    #[test]
    fn malformed_tokens_are_refused_with_one_shapeless_error() {
        for bad in [
            "",
            "nodot",
            "ABCDEF0123456789abcdef01.AAAA",
            "0123456789abcdef01234567.AAAA",
            "0123456789abcdef01234567.***",
            "0123456789abcdef01234567",
            "0123456789abcdef0123456.QUJD",
        ] {
            assert_eq!(parse(bad), Err(TokenFormatError), "{bad:?}");
        }
    }

    #[test]
    fn base64url_matches_the_rfc_vectors() {
        assert_eq!(base64url_encode(b""), "");
        assert_eq!(base64url_encode(b"f"), "Zg");
        assert_eq!(base64url_encode(b"fo"), "Zm8");
        assert_eq!(base64url_encode(b"foo"), "Zm9v");
        assert_eq!(base64url_encode(&[0xfb, 0xff]), "-_8");
        for input in [&b""[..], b"f", b"fo", b"foo", b"foob", b"fooba", b"foobar"] {
            assert_eq!(
                base64url_decode(&base64url_encode(input)).expect("decode"),
                input
            );
        }
        assert!(base64url_decode("Z").is_none());
        assert!(base64url_decode("Zm9v=").is_none());
    }

    #[test]
    fn two_mints_never_collide() {
        let key = [1u8; 32];
        let a = mint(&key, &[0u8; PIN_LEN]).expect("a");
        let b = mint(&key, &[0u8; PIN_LEN]).expect("b");
        assert_ne!(a.public_id, b.public_id);
        assert_ne!(a.secret_hmac, b.secret_hmac);
    }
}
