// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! Process-wide HMAC secret used to sign verdict cookies.
//!
//! A single 32-byte random secret is published via [`ArcSwap`] at
//! startup and hot-swapped on each call to [`rotate`]. Every verify
//! / sign operation on the hot path reads through [`handle`],
//! which returns a lock-free `Arc<[u8; 32]>` snapshot — a rotation
//! does not block in-flight requests.
//!
//! Storage of the secret in SQLite (`global_settings.bot_hmac_secret`)
//! is handled by the caller (`lorica-config` + `lorica::reload`);
//! this crate only owns the in-memory view. Persisting the bytes
//! in the config DB (rather than, say, a systemd credential) keeps
//! the first-boot path simple — the same migration that creates
//! the `global_settings` table carries the default empty value.
//!
//! ## Threading
//!
//! `handle()` is safe to call from any thread / task. The returned
//! `Arc<[u8; 32]>` is cheap to clone (Arc refcount bump) and does
//! not pin the resolver — dropping the snapshot on the calling
//! task is idiomatic.
//!
//! ## Rotation contract
//!
//! - **Atomic.** A single `ArcSwap::store` call replaces the live
//!   snapshot. In-flight verify calls see either the old or the
//!   new secret, never a partial replacement.
//! - **Forward-only.** Rotation overwrites the slot; previous
//!   secrets are dropped once all live references elapse. No
//!   historical secret is retained to "retry" an old cookie — by
//!   design, rotation invalidates outstanding verdicts.
//! - **Idempotent.** Rotating with the same bytes is a legal no-op.

use std::sync::Arc;

use arc_swap::ArcSwap;
use once_cell::sync::Lazy;
use rand::RngCore;

/// Size of the HMAC secret in bytes. 32 bytes = the full SHA-256
/// block and the RustCrypto `hmac::Hmac<Sha256>` native key size;
/// anything shorter forces internal padding without adding entropy.
pub const SECRET_LEN: usize = 32;

/// Process-wide secret slot. `None` until [`install`] has been
/// called at least once — callers that read the secret before
/// startup has finished get a typed error rather than a random
/// panic from `unwrap`.
static SECRET: Lazy<ArcSwap<Option<Arc<[u8; SECRET_LEN]>>>> =
    Lazy::new(|| ArcSwap::from_pointee(None));

/// Install the initial secret. Called from `lorica::reload`'s
/// `apply_bot_secret_from_store` on every config reload, and from
/// the first-boot path after [`generate`] produces the row-zero
/// secret. Second and subsequent calls are handled identically,
/// they simply publish the new bytes; callers that want to
/// "rotate" an existing secret should use [`rotate`] which is the
/// intentionally-named public alias.
pub fn install(bytes: [u8; SECRET_LEN]) {
    SECRET.store(Arc::new(Some(Arc::new(bytes))));
}

/// Rotate the in-memory HMAC secret. Semantically identical to
/// [`install`]; kept as a separate name so `grep rotate_hmac_secret`
/// in future audit trails finds the call site that corresponds to
/// the cert-renewal path.
pub fn rotate(bytes: [u8; SECRET_LEN]) {
    install(bytes);
}

/// Read the current secret. Returns `None` before the first
/// [`install`] has run. Callers on the hot path should propagate
/// the `None` to the verifier, which treats it as a hard
/// `ChallengeError::Internal` (cookie verification impossible
/// without a secret).
pub fn handle() -> Option<Arc<[u8; SECRET_LEN]>> {
    (**SECRET.load()).clone()
}

/// Produce a fresh 32-byte secret from the OS CSPRNG. Used by the
/// supervisor's first-boot path and by the cert-renewal path to
/// mint a new secret for [`rotate`].
///
/// Uses `rand::rngs::OsRng` (syscall-backed on Linux: getrandom on
/// glibc-based distros, /dev/urandom as the fallback). Blocks only
/// if the kernel's random pool is not yet seeded, which on a
/// modern Linux box is ≤ 10 ms at cold boot and zero thereafter.
pub fn generate() -> [u8; SECRET_LEN] {
    let mut out = [0u8; SECRET_LEN];
    rand::rngs::OsRng.fill_bytes(&mut out);
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // All tests in this module mutate the global `SECRET` slot, so
    // they must run serially. Without this mutex, cargo test's
    // parallel scheduler produces flaky failures (one test reads
    // `handle()` while another's `install` is the most recent
    // write, and the captured Arc refers to bytes that test did
    // not expect).
    static TEST_LOCK: Mutex<()> = Mutex::new(());

    #[test]
    fn handle_is_some_after_install() {
        let _guard = TEST_LOCK.lock().unwrap();
        install([0xCCu8; SECRET_LEN]);
        // After at least one install has run, handle() must be
        // Some. This verifies the installed-value visibility
        // contract without making any claim about state prior to
        // the first install (which varies by test ordering).
        assert!(handle().is_some());
    }

    #[test]
    fn install_publishes_bytes() {
        let _guard = TEST_LOCK.lock().unwrap();
        let key = [0x42u8; SECRET_LEN];
        install(key);
        let got = handle().expect("installed, must be Some");
        assert_eq!(*got, key);
    }

    #[test]
    fn generate_is_non_deterministic() {
        // `generate` does not touch the global slot, so it is
        // free to run without the lock. Two 256-bit CSPRNG draws
        // colliding would be a ~2^-256 event; a collision here
        // is a real bug.
        let a = generate();
        let b = generate();
        assert_ne!(a, b);
    }

    #[test]
    fn rotate_replaces_current_snapshot() {
        let _guard = TEST_LOCK.lock().unwrap();
        install([0xA1u8; SECRET_LEN]);
        let first = handle().unwrap();
        assert_eq!(*first, [0xA1u8; SECRET_LEN]);

        let new_key = [0xB2u8; SECRET_LEN];
        rotate(new_key);
        let second = handle().unwrap();
        assert_eq!(*second, new_key);

        // The original Arc is still alive (we are holding it) and
        // carries the old bytes — ArcSwap dropped its slot pointer
        // but did not mutate the payload.
        assert_eq!(*first, [0xA1u8; SECRET_LEN]);
    }
}
