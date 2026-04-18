// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Bot-protection challenge primitives for Lorica.
//!
//! This crate is the self-contained implementation of the three
//! challenge modes described in `docs/architecture/bot-protection.md`:
//!
//! - **Cookie mode** (passive): only relies on the HMAC-signed
//!   verdict cookie exported by [`cookie::sign`] / [`cookie::verify`].
//! - **JavaScript proof-of-work**: [`pow::Challenge::new`] and
//!   [`pow::verify_solution`].
//! - **Image captcha**: [`captcha::generate`] renders a PNG + the
//!   expected solution text.
//!
//! All three modes share the same verdict cookie; a successful
//! solution minted via any mode issues a cookie that is honoured on
//! subsequent requests against the same route / IP prefix.
//!
//! The process-wide HMAC secret lifecycle lives in [`secret`]:
//! a 32-byte random key, hot-swappable via [`secret::rotate`] on
//! certificate renewal, readable lock-free from the hot path via
//! [`secret::handle`]. Rotation invalidates all outstanding
//! verdict cookies — a documented, bounded UX cost tied to cert
//! renewal cadence (≤ 90 days on default Let's Encrypt).
//!
//! ## Threading
//!
//! Every public function is `Send + Sync` and safe to call from
//! multiple request-handler tasks concurrently. State (the HMAC
//! secret) is wrapped in `ArcSwap<[u8; 32]>` so the rotation path
//! does not block lookups.
//!
//! ## No `unwrap` on user-reachable paths
//!
//! Every public function that accepts untrusted input ([`cookie::verify`],
//! [`pow::verify_solution`], the captcha verifier in [`captcha::verify`])
//! returns a typed `Result` and never panics on malformed bytes,
//! garbage UTF-8, wrong lengths, or expired timestamps.

pub mod captcha;
pub mod cookie;
pub mod pow;
pub mod render;
pub mod secret;

use thiserror::Error;

/// Typed error surface at the public boundary. Each mode produces
/// its own subset of these variants; callers typically only need to
/// distinguish "reject + show the challenge again" from
/// "something is badly wrong, log it".
#[derive(Debug, Error)]
pub enum ChallengeError {
    /// Cookie / PoW / captcha payload failed shape validation
    /// (wrong length, not base64, not UTF-8, missing field). Fail
    /// silently on the hot path — clients that tamper with the
    /// cookie just get a new challenge.
    #[error("payload malformed: {0}")]
    Malformed(&'static str),

    /// HMAC tag does not match the payload. Either the secret was
    /// rotated while the cookie was in flight (expected; re-
    /// challenge the user) or the cookie was forged (rare; log at
    /// the caller).
    #[error("HMAC verification failed")]
    BadSignature,

    /// Cookie / challenge expired. Verifier applies a ± 30 s clock-
    /// skew grace to tolerate drift between Lorica and the client.
    #[error("expired: {reason}")]
    Expired { reason: &'static str },

    /// PoW solution did not meet the difficulty target.
    #[error("proof-of-work solution does not satisfy difficulty {difficulty} zero bits")]
    PowBelowDifficulty { difficulty: u8 },

    /// Captcha answer did not match the expected text.
    #[error("captcha answer mismatch")]
    CaptchaMismatch,

    /// An internal invariant broke (RNG failure, image-encoder
    /// failure). These are fatal-ish: retry at the caller, surface
    /// to metrics as a health signal.
    #[error("internal: {0}")]
    Internal(&'static str),
}

pub type Result<T> = std::result::Result<T, ChallengeError>;

/// Which mode issued a given verdict cookie. Stamped into the
/// cookie payload so metrics / dashboard can break down outcomes
/// by mode ("how many visitors passed the PoW vs. solved the
/// captcha").
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Mode {
    Cookie = 1,
    Javascript = 2,
    Captcha = 3,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Cookie => "cookie",
            Mode::Javascript => "javascript",
            Mode::Captcha => "captcha",
        }
    }

    /// Parse from the single-byte wire form stored in the cookie
    /// payload. Returns `None` for any other byte value.
    pub fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(Mode::Cookie),
            2 => Some(Mode::Javascript),
            3 => Some(Mode::Captcha),
            _ => None,
        }
    }
}

/// Client-IP prefix used as the second component of the verdict
/// cookie binding. See `docs/architecture/bot-protection.md` § 4.2.
///
/// IPv4 addresses are truncated to `/24`, IPv6 to `/64`. A cookie
/// issued for a client at `203.0.113.42` will validate against any
/// client at `203.0.113.0/24`; the same cookie will not validate
/// against `203.0.114.0/24`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum IpPrefix {
    V4([u8; 4]),  // first 3 bytes significant, byte 3 zero-padded
    V6([u8; 16]), // first 8 bytes significant, bytes 8..16 zero-padded
}

impl IpPrefix {
    /// Build the prefix from a client IP. v4 keeps the first 24
    /// bits (one /24 subnet); v6 keeps the first 64 bits (one
    /// typical per-subscriber ISP allocation).
    pub fn from_ip(ip: std::net::IpAddr) -> Self {
        match ip {
            std::net::IpAddr::V4(v4) => {
                let o = v4.octets();
                IpPrefix::V4([o[0], o[1], o[2], 0])
            }
            std::net::IpAddr::V6(v6) => {
                let o = v6.octets();
                let mut out = [0u8; 16];
                out[..8].copy_from_slice(&o[..8]);
                IpPrefix::V6(out)
            }
        }
    }

    /// Wire-format bytes that go into the HMAC payload. 4 bytes for
    /// v4 (the zero-padded /24), 8 bytes for v6 (the significant /64).
    /// Caller pre-pends a 1-byte discriminator when serialising so
    /// the verifier can parse v4 vs v6 without ambiguity.
    pub fn as_bytes(&self) -> &[u8] {
        match self {
            IpPrefix::V4(b) => &b[..3],
            IpPrefix::V6(b) => &b[..8],
        }
    }

    /// 1 = IPv4, 2 = IPv6. Stored as the discriminator byte in the
    /// cookie payload so the verifier knows how many IP bytes to
    /// consume without relying on length arithmetic.
    pub fn discriminator(&self) -> u8 {
        match self {
            IpPrefix::V4(_) => 1,
            IpPrefix::V6(_) => 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn mode_roundtrip() {
        for m in [Mode::Cookie, Mode::Javascript, Mode::Captcha] {
            assert_eq!(Mode::from_u8(m as u8), Some(m));
        }
        assert_eq!(Mode::from_u8(0), None);
        assert_eq!(Mode::from_u8(4), None);
        assert_eq!(Mode::from_u8(255), None);
    }

    #[test]
    fn ip_prefix_v4_zeroes_low_octet() {
        let ip = IpAddr::V4(Ipv4Addr::new(203, 0, 113, 42));
        let p = IpPrefix::from_ip(ip);
        match p {
            IpPrefix::V4(b) => assert_eq!(b, [203, 0, 113, 0]),
            other => panic!("expected V4 prefix, got {other:?}"),
        }
        // Significant wire bytes skip the zero-padded 4th octet.
        assert_eq!(IpPrefix::from_ip(ip).as_bytes(), &[203, 0, 113]);
    }

    #[test]
    fn ip_prefix_v4_same_slash24_matches() {
        let a = IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
        let b = IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 254)));
        assert_eq!(a, b);
    }

    #[test]
    fn ip_prefix_v4_different_slash24_differs() {
        let a = IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1)));
        let b = IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::new(203, 0, 114, 1)));
        assert_ne!(a, b);
    }

    #[test]
    fn ip_prefix_v6_keeps_first_eight_bytes() {
        let ip = IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x0db8, 0x85a3, 0x0000, // /64 boundary
            0x0000, 0x8a2e, 0x0370, 0x7334,
        ));
        let p = IpPrefix::from_ip(ip);
        match p {
            IpPrefix::V6(b) => {
                // First 8 bytes kept.
                assert_eq!(&b[..8], &[0x20, 0x01, 0x0d, 0xb8, 0x85, 0xa3, 0x00, 0x00]);
                // Low 8 zeroed.
                assert_eq!(&b[8..], &[0u8; 8]);
            }
            other => panic!("expected V6 prefix, got {other:?}"),
        }
    }

    #[test]
    fn ip_prefix_v6_same_slash64_matches() {
        let a = IpPrefix::from_ip(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x0db8, 0x85a3, 0x0000, 0x0001, 0, 0, 1,
        )));
        let b = IpPrefix::from_ip(IpAddr::V6(Ipv6Addr::new(
            0x2001, 0x0db8, 0x85a3, 0x0000, 0xffff, 0xffff, 0xffff, 0xffff,
        )));
        assert_eq!(a, b);
    }

    #[test]
    fn ip_prefix_discriminators_distinct() {
        let v4 = IpPrefix::from_ip(IpAddr::V4(Ipv4Addr::new(1, 2, 3, 4)));
        let v6 = IpPrefix::from_ip(IpAddr::V6(Ipv6Addr::LOCALHOST));
        assert_eq!(v4.discriminator(), 1);
        assert_eq!(v6.discriminator(), 2);
    }
}
