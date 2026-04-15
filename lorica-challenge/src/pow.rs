// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! JavaScript proof-of-work challenge primitives.
//!
//! The challenge: find a u64 `counter` such that
//! `SHA-256(nonce || counter_decimal_bytes)` has at least `N`
//! leading zero bits, for N in 14..=22.
//!
//! The browser runs the search via `crypto.subtle.digest`; Lorica
//! runs it at construction time only as a sanity-check inside the
//! test suite (the server-side work is purely the O(1) verify).
//!
//! Wire format:
//! - Challenge: `nonce` (16 raw bytes, hex-encoded for JS
//!   consumption), `difficulty` (u8), `expires_at` (u64 seconds
//!   since UNIX epoch).
//! - Solution: `nonce` (same hex bytes), `counter` (decimal u64).
//!
//! See `docs/architecture/bot-protection.md` § 5 for the full
//! specification.

use rand::RngCore;
use sha2::{Digest, Sha256};

use crate::{ChallengeError, Result};

/// Hard lower bound. Anything below 14 bits solves in < 10 ms on
/// 2024 hardware — effectively no bot cost. Keeping the floor
/// external-to-the-config means the API validator can reject
/// misconfiguration cleanly.
pub const MIN_DIFFICULTY: u8 = 14;

/// Hard upper bound. 22 bits is ~12 s median solve on a mid-range
/// laptop. Above 22 the mobile UX degrades to "user gives up"
/// territory and the operator should escalate to captcha mode
/// instead.
pub const MAX_DIFFICULTY: u8 = 22;

/// Default difficulty used by the config validator when the
/// operator does not pick one. Chosen to pass unmodified on
/// desktop (~800 ms) and tolerably on mobile (~2 s).
pub const DEFAULT_DIFFICULTY: u8 = 18;

/// Default challenge TTL. Once a challenge's `expires_at` is past,
/// even a correctly-mined counter is rejected — so a bot cannot
/// pre-compute a pool of solutions and pay the cost once.
pub const DEFAULT_CHALLENGE_TTL_S: u64 = 300;

/// Length of the server-side nonce in raw bytes. Hex-encoded on
/// the wire this is 32 chars, well under the ~512-char HTTP form
/// field sanity cap every browser enforces.
pub const NONCE_LEN: usize = 16;

/// A freshly-minted challenge. Contents are safe to serialise
/// into the HTML page verbatim (nonce is non-secret, difficulty
/// and expires_at are just UX hints); no HMAC wrap needed at this
/// layer because the downstream cookie already carries the HMAC.
#[derive(Debug, Clone)]
pub struct Challenge {
    /// Random challenge material. 16 bytes = 128 bits of entropy,
    /// adequate to make nonce collisions across concurrent
    /// clients astronomically unlikely.
    pub nonce: [u8; NONCE_LEN],
    pub difficulty: u8,
    pub expires_at: u64,
}

impl Challenge {
    /// Mint a fresh challenge at the given difficulty and TTL.
    /// Returns [`ChallengeError::Internal`] on RNG failure.
    pub fn new(difficulty: u8, now: u64, ttl_s: u64) -> Result<Self> {
        if !(MIN_DIFFICULTY..=MAX_DIFFICULTY).contains(&difficulty) {
            return Err(ChallengeError::Internal(
                "difficulty outside 14..=22 (config validator should have caught this)",
            ));
        }
        let mut nonce = [0u8; NONCE_LEN];
        rand::rngs::OsRng.fill_bytes(&mut nonce);
        Ok(Challenge {
            nonce,
            difficulty,
            expires_at: now.saturating_add(ttl_s),
        })
    }

    /// Hex-encoded nonce for the JS snippet. Format matches what
    /// `crypto.subtle.digest` consumers expect.
    pub fn nonce_hex(&self) -> String {
        let mut out = String::with_capacity(NONCE_LEN * 2);
        for b in self.nonce.iter() {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }
}

/// Verify a submitted solution. Returns `Ok(())` on success; a
/// typed `ChallengeError` otherwise.
///
/// - `nonce_hex`: the hex string echoed back by the client (from
///   the original challenge).
/// - `counter`: the decimal u64 the client claims satisfies the
///   target.
/// - `now`: current wall-clock time in seconds since UNIX epoch.
///   Callers pass this explicitly so tests can pin the clock.
/// - `expected_difficulty`, `expected_expires_at`: copied from the
///   original [`Challenge`]. The caller is responsible for pairing
///   these correctly (e.g. by embedding them in the challenge-
///   side HTML's HMAC-signed envelope, or by reading them from
///   the per-session stash).
pub fn verify_solution(
    nonce_hex: &str,
    counter: u64,
    now: u64,
    expected_difficulty: u8,
    expected_expires_at: u64,
) -> Result<()> {
    if now > expected_expires_at {
        return Err(ChallengeError::Expired {
            reason: "PoW challenge expires_at in the past",
        });
    }
    if !(MIN_DIFFICULTY..=MAX_DIFFICULTY).contains(&expected_difficulty) {
        // Defence-in-depth: the config validator should have
        // caught this, but verifying a 0-bit challenge would let
        // any byte string through.
        return Err(ChallengeError::Internal(
            "expected_difficulty outside 14..=22",
        ));
    }
    let nonce_bytes = decode_hex(nonce_hex)?;
    if nonce_bytes.len() != NONCE_LEN {
        return Err(ChallengeError::Malformed(
            "nonce hex does not decode to 16 bytes",
        ));
    }

    // Compose the preimage. The browser's fetch path hashes
    // `hex_nonce + counter_decimal_string` (via JS string
    // concatenation + TextEncoder), so we match that shape
    // exactly. Keeping hex on the preimage side avoids a
    // sometimes-confusing "why doesn't JS match Rust" bug where
    // the two sides disagree about the bytes they fed to SHA-256.
    let mut hasher = Sha256::new();
    hasher.update(nonce_hex.as_bytes());
    hasher.update(counter.to_string().as_bytes());
    let digest = hasher.finalize();

    if !has_leading_zero_bits(&digest, expected_difficulty) {
        return Err(ChallengeError::PowBelowDifficulty {
            difficulty: expected_difficulty,
        });
    }
    Ok(())
}

/// Return true iff the first `n` bits of `bytes` are zero.
/// `n` may span across byte boundaries — the last partial byte is
/// masked to the remaining bit count.
///
/// Kept `pub(crate)` so tests in other modules (and a future
/// debug dump helper) can reuse it without copying the bit
/// arithmetic.
pub(crate) fn has_leading_zero_bits(bytes: &[u8], n: u8) -> bool {
    let full_bytes = (n / 8) as usize;
    let remainder = (n % 8) as usize;
    if bytes.len() < full_bytes + if remainder > 0 { 1 } else { 0 } {
        return false;
    }
    if bytes[..full_bytes].iter().any(|&b| b != 0) {
        return false;
    }
    if remainder == 0 {
        return true;
    }
    // Check top `remainder` bits of the next byte are zero. The
    // mask keeps the leading bits: for remainder=5 the mask is
    // 0b11111000 = 0xF8 (5 leading bits must be zero).
    let mask = 0xFFu8 << (8 - remainder);
    bytes[full_bytes] & mask == 0
}

/// Decode a hex string into raw bytes. Accepts lower- or upper-
/// case hex; rejects anything else. Kept private to this module
/// so the only public surface consuming untrusted hex is the
/// verifier above.
fn decode_hex(s: &str) -> Result<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return Err(ChallengeError::Malformed("nonce hex has odd length"));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let bytes = s.as_bytes();
    for chunk in bytes.chunks(2) {
        let hi = hex_digit(chunk[0])?;
        let lo = hex_digit(chunk[1])?;
        out.push(hi << 4 | lo);
    }
    Ok(out)
}

fn hex_digit(c: u8) -> Result<u8> {
    match c {
        b'0'..=b'9' => Ok(c - b'0'),
        b'a'..=b'f' => Ok(c - b'a' + 10),
        b'A'..=b'F' => Ok(c - b'A' + 10),
        _ => Err(ChallengeError::Malformed("nonce hex contains non-hex char")),
    }
}

/// Naive PoW miner used by tests. Iterates `counter` from 0
/// upwards and returns the first value that clears the
/// difficulty target. NOT exposed outside `cfg(test)` because
/// production has no legitimate reason to mine on the server
/// side — the whole point is that the client pays the cost.
#[cfg(test)]
pub(crate) fn mine(nonce_hex: &str, difficulty: u8) -> u64 {
    for counter in 0u64..u64::MAX {
        let mut hasher = Sha256::new();
        hasher.update(nonce_hex.as_bytes());
        hasher.update(counter.to_string().as_bytes());
        if has_leading_zero_bits(&hasher.finalize(), difficulty) {
            return counter;
        }
    }
    unreachable!("u64 range exhausted without a solution at difficulty {difficulty}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn challenge_new_rejects_below_min_difficulty() {
        let err = Challenge::new(13, 0, 300).unwrap_err();
        assert!(matches!(err, ChallengeError::Internal(_)));
    }

    #[test]
    fn challenge_new_rejects_above_max_difficulty() {
        let err = Challenge::new(23, 0, 300).unwrap_err();
        assert!(matches!(err, ChallengeError::Internal(_)));
    }

    #[test]
    fn challenge_new_accepts_boundary_values() {
        assert!(Challenge::new(14, 0, 300).is_ok());
        assert!(Challenge::new(22, 0, 300).is_ok());
    }

    #[test]
    fn challenge_nonce_hex_roundtrip() {
        let c = Challenge::new(14, 0, 300).unwrap();
        let hex = c.nonce_hex();
        assert_eq!(hex.len(), NONCE_LEN * 2);
        let decoded = decode_hex(&hex).unwrap();
        assert_eq!(decoded, c.nonce);
    }

    #[test]
    fn verify_rejects_malformed_nonce() {
        let err = verify_solution("not-hex!", 0, 100, 14, 200).unwrap_err();
        assert!(matches!(err, ChallengeError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn verify_rejects_wrong_length_nonce() {
        // 30 hex chars -> 15 bytes, one short of NONCE_LEN.
        let err = verify_solution("aabbccddeeff00112233445566778", 0, 100, 14, 200)
            .unwrap_err();
        assert!(matches!(err, ChallengeError::Malformed(_)), "{err:?}");
    }

    #[test]
    fn verify_rejects_expired_challenge() {
        let err = verify_solution(
            "00000000000000000000000000000000",
            0,
            1_000, // now
            14,
            500, // expires_at in the past
        )
        .unwrap_err();
        assert!(matches!(err, ChallengeError::Expired { .. }), "{err:?}");
    }

    #[test]
    fn verify_rejects_bad_expected_difficulty() {
        let err = verify_solution(
            "00000000000000000000000000000000",
            0,
            100,
            13, // below MIN
            500,
        )
        .unwrap_err();
        assert!(matches!(err, ChallengeError::Internal(_)), "{err:?}");
    }

    #[test]
    fn verify_accepts_a_correctly_mined_solution_at_low_difficulty() {
        // 14 bits = ~16k attempts on average; mine() is quick.
        let nonce_hex = "0011223344556677aabbccddeeff0011";
        let counter = mine(nonce_hex, 14);
        assert!(verify_solution(nonce_hex, counter, 100, 14, 500).is_ok());
    }

    #[test]
    fn verify_rejects_off_by_one_counter() {
        let nonce_hex = "0011223344556677aabbccddeeff0011";
        let counter = mine(nonce_hex, 14);
        // A counter that does NOT clear 14 leading zero bits must
        // fail. Use `counter + 1`: almost always fails at 14 bits.
        let err = verify_solution(nonce_hex, counter + 1, 100, 14, 500);
        // 1 in 16384 chance of counter+1 also clearing 14 bits;
        // if so the test would be flaky. Retry the mine by bumping
        // the nonce instead — but at 14 bits that risk is
        // acceptable given this is deterministic on a given
        // fixture. If this flakes, pick a different nonce_hex
        // literal.
        assert!(
            matches!(err, Err(ChallengeError::PowBelowDifficulty { .. })),
            "off-by-one solve was accidentally also valid; rerun or pick a different nonce"
        );
    }

    #[test]
    fn has_leading_zero_bits_byte_aligned() {
        // 16 bits = 2 zero bytes; [0, 0, 1, ...] passes.
        assert!(has_leading_zero_bits(&[0, 0, 1, 2, 3], 16));
        // But 17 bits requires the top bit of byte 2 to be zero;
        // byte 2 = 0x01 has its top bit zero, so 17 passes. Use
        // 0x80 to force a failure.
        assert!(has_leading_zero_bits(&[0, 0, 0x01], 17));
        assert!(!has_leading_zero_bits(&[0, 0, 0x80], 17));
    }

    #[test]
    fn has_leading_zero_bits_cross_byte() {
        // 13 bits = 1 full zero byte + 5 zero bits in the next.
        // Second byte mask is 0b11111000 = 0xF8; top 5 bits zero.
        assert!(has_leading_zero_bits(&[0x00, 0x07], 13)); // 0x07 = 00000111
        assert!(!has_leading_zero_bits(&[0x00, 0x08], 13)); // 0x08 = 00001000
    }

    #[test]
    fn has_leading_zero_bits_rejects_short_input() {
        // 16 bits required, only 1 byte supplied -> must fail
        // rather than panic / over-read.
        assert!(!has_leading_zero_bits(&[0x00], 16));
    }
}
