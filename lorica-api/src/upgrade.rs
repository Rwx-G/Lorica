//! Hot binary-upgrade verification + staging (Story 8.4).
//!
//! This module owns the operator-facing `POST /api/v1/system/upgrade`
//! endpoint and the Ed25519 verification it gates uploads with. The
//! operator uploads the new `lorica` executable plus a detached
//! Ed25519 signature over the executable bytes; the server verifies
//! the signature against a configured public key, then STAGES the
//! verified binary at `<data_dir>/upgrade/lorica.new`.
//!
//! Scope boundary: this chunk verifies + stages only. The actual
//! zero-downtime handoff (execve + listening-socket FD passing +
//! connection drain) lands in Story 8.4 chunk 2 and wires into the
//! [`trigger_handoff`] seam left at the end of the staging path.
//!
//! ## Encoding contract
//!
//! - Public key file ([`GlobalSettings::upgrade_signing_pubkey_path`]):
//!   the 32-byte Ed25519 verifying key, hex-encoded as a single
//!   64-character line. Trailing whitespace is tolerated.
//! - `signature` multipart part: the 64-byte detached signature,
//!   hex-encoded (128 characters).
//! - `binary` multipart part: the raw executable bytes (not encoded).
//!
//! [`GlobalSettings::upgrade_signing_pubkey_path`]: lorica_config::models::GlobalSettings::upgrade_signing_pubkey_path

use std::io::Write as _;
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};

use axum::extract::{Extension, Multipart};
use axum::Json;
use ed25519_dalek::{Signature, VerifyingKey};
use thiserror::Error;

use crate::db::db_blocking;
use crate::error::{json_data, ApiError};
use crate::metrics::record_hot_upgrade;
use crate::server::AppState;

/// Length in bytes of an Ed25519 verifying key.
const PUBLIC_KEY_LEN: usize = 32;

/// Length in bytes of an Ed25519 detached signature.
const SIGNATURE_LEN: usize = 64;

/// File name of the staged, verified binary inside `<data_dir>/upgrade/`.
const STAGED_BINARY_NAME: &str = "lorica.new";

/// Temp file the staged binary is written to before the atomic rename
/// onto [`STAGED_BINARY_NAME`].
const STAGED_BINARY_TMP_NAME: &str = ".lorica.new.tmp";

/// Errors raised by the hot binary-upgrade verification + staging path.
#[derive(Debug, Error)]
pub enum UpgradeError {
    /// No `upgrade_signing_pubkey_path` is configured, so the endpoint
    /// has no key to verify against and refuses every upload rather
    /// than trusting an unsigned binary.
    #[error("no upgrade signing key configured")]
    NoSigningKey,

    /// The configured public-key file does not hold a 32-byte Ed25519
    /// verifying key hex-encoded as 64 characters.
    #[error("upgrade signing public key is malformed (expected 64 hex chars / 32-byte Ed25519 key)")]
    BadPublicKey,

    /// The detached signature is not a 64-byte Ed25519 signature.
    #[error("detached signature is malformed (expected 64-byte Ed25519 signature)")]
    BadSignature,

    /// The signature does not verify against the configured key for the
    /// uploaded binary bytes (tampered binary, wrong key, or wrong sig).
    #[error("binary signature does not match the configured signing key")]
    SignatureMismatch,

    /// Reading the key file or staging the binary failed at the I/O
    /// boundary.
    #[error("upgrade I/O error: {0}")]
    Io(String),
}

/// Verify a detached Ed25519 `signature` over `binary` against
/// `public_key`.
///
/// `public_key` must be the 32 raw bytes of an Ed25519 verifying key
/// and `signature` the 64 raw bytes of a detached signature (the
/// caller decodes any transport encoding first). Uses `verify_strict`
/// to reject the small-order / non-canonical edge cases that plain
/// `verify` accepts.
///
/// ```
/// use ed25519_dalek::{Signer, SigningKey};
/// use lorica_api::upgrade::verify_binary_signature;
///
/// let signing = SigningKey::from_bytes(&[7u8; 32]);
/// let verifying = signing.verifying_key();
/// let binary = b"new lorica binary bytes";
/// let sig = signing.sign(binary);
///
/// verify_binary_signature(binary, &sig.to_bytes(), verifying.as_bytes())
///     .expect("a freshly produced signature must verify");
/// ```
pub fn verify_binary_signature(
    binary: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<(), UpgradeError> {
    let key_bytes: [u8; PUBLIC_KEY_LEN] = public_key
        .try_into()
        .map_err(|_| UpgradeError::BadPublicKey)?;
    let verifying_key: VerifyingKey =
        VerifyingKey::from_bytes(&key_bytes).map_err(|_| UpgradeError::BadPublicKey)?;
    let signature: Signature =
        Signature::from_slice(signature).map_err(|_| UpgradeError::BadSignature)?;
    verifying_key
        .verify_strict(binary, &signature)
        .map_err(|_| UpgradeError::SignatureMismatch)
}

/// Load the configured Ed25519 verifying key as 32 raw bytes.
///
/// Reads `upgrade_signing_pubkey_path` from the global settings; when
/// unset (or blank) returns [`UpgradeError::NoSigningKey`] so the
/// endpoint can 400 with a clear "not configured" message. Otherwise
/// reads the file and hex-decodes the single 64-character line into 32
/// bytes. No key is compiled into the binary, by design: a dev key
/// must never be trusted in production.
///
/// Async because the path lives behind the store's async mutex; the
/// file read itself is a small one-shot.
pub async fn load_signing_public_key(state: &AppState) -> Result<Vec<u8>, UpgradeError> {
    let path: Option<String> = db_blocking(&state.store, |store| store.get_global_settings())
        .await
        .map_err(|e| UpgradeError::Io(e.to_string()))?
        .upgrade_signing_pubkey_path;

    let Some(path) = path.filter(|p| !p.trim().is_empty()) else {
        return Err(UpgradeError::NoSigningKey);
    };

    let raw: String = std::fs::read_to_string(&path).map_err(|e| UpgradeError::Io(e.to_string()))?;
    decode_public_key_hex(raw.trim())
}

/// Decode a hex-encoded Ed25519 verifying key (64 hex chars -> 32 bytes).
fn decode_public_key_hex(s: &str) -> Result<Vec<u8>, UpgradeError> {
    decode_hex(s)
        .filter(|bytes| bytes.len() == PUBLIC_KEY_LEN)
        .ok_or(UpgradeError::BadPublicKey)
}

/// Decode an even-length hex string into bytes. Returns `None` on an
/// odd length or any non-hex character.
fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Lower-case hex encoding, used for the staged binary's SHA-256 in the
/// response body.
fn encode_hex(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Hand the staged binary off to the supervisor's zero-downtime restart
/// (Story 8.4 chunk 2): execve of the new binary, listening-socket FD
/// passing, connection drain.
///
/// The verify+stage path runs inside the API server, which has no access
/// to the listening sockets or the worker manager; those live in the
/// supervisor process that owns this API task. So rather than perform the
/// handoff here, we signal the supervisor over the
/// [`AppState::upgrade_trigger`] channel with the staged path and let its
/// main control loop drive the fork/exec/drain/rollback state machine.
///
/// In single-process mode (and tests) `upgrade_trigger` is `None`: there
/// is no supervisor to fork a replacement, so the binary is staged only
/// and a warning is logged. The HTTP response is unchanged either way -
/// staging succeeded - so the operator always learns the binary is in
/// place; only the live swap is conditional on running under a
/// supervisor.
pub async fn trigger_handoff(state: &AppState, staged_path: &Path) {
    match &state.upgrade_trigger {
        Some(trigger) => match trigger.try_send(staged_path.to_path_buf()) {
            Ok(()) => {
                tracing::info!(
                    staged_path = %staged_path.display(),
                    "hot upgrade staged; signalled supervisor to begin handoff"
                );
            }
            Err(e) => {
                // A full/closed channel means a handoff is already in
                // flight or the supervisor is gone. Surface it; the
                // binary is staged and the operator can retry.
                tracing::error!(
                    error = %e,
                    staged_path = %staged_path.display(),
                    "hot upgrade staged but the handoff signal could not be delivered \
                     (a handoff may already be in progress); binary left staged"
                );
            }
        },
        None => {
            tracing::warn!(
                staged_path = %staged_path.display(),
                "hot upgrade staged but no handoff trigger is wired (single-process mode); \
                 the binary is staged only and will take effect on the next restart"
            );
        }
    }
}

/// Stage `binary` at `<data_dir>/upgrade/lorica.new` with mode 0755,
/// writing to a temp file first and atomically renaming into place so a
/// crash mid-write never leaves a half-written `lorica.new`. The
/// `upgrade` directory is created 0700 (operator-only).
fn stage_binary(data_dir: &Path, binary: &[u8]) -> Result<PathBuf, UpgradeError> {
    let upgrade_dir: PathBuf = data_dir.join("upgrade");
    std::fs::create_dir_all(&upgrade_dir).map_err(|e| UpgradeError::Io(e.to_string()))?;
    std::fs::set_permissions(&upgrade_dir, std::fs::Permissions::from_mode(0o700))
        .map_err(|e| UpgradeError::Io(e.to_string()))?;

    let final_path: PathBuf = upgrade_dir.join(STAGED_BINARY_NAME);
    let tmp_path: PathBuf = upgrade_dir.join(STAGED_BINARY_TMP_NAME);

    {
        let mut file = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o755)
            .open(&tmp_path)
            .map_err(|e| UpgradeError::Io(e.to_string()))?;
        file.write_all(binary)
            .map_err(|e| UpgradeError::Io(e.to_string()))?;
        file.sync_all()
            .map_err(|e| UpgradeError::Io(e.to_string()))?;
    }

    // Re-assert the mode explicitly: the umask masks the OpenOptions
    // mode at creation, so a 0022 umask would otherwise drop the
    // group/other execute bits we want on an executable.
    std::fs::set_permissions(&tmp_path, std::fs::Permissions::from_mode(0o755))
        .map_err(|e| UpgradeError::Io(e.to_string()))?;
    std::fs::rename(&tmp_path, &final_path).map_err(|e| UpgradeError::Io(e.to_string()))?;

    Ok(final_path)
}

/// POST /api/v1/system/upgrade - verify + stage a new `lorica` binary.
///
/// Accepts a `multipart/form-data` body with two parts: `binary` (the
/// raw new-executable bytes) and `signature` (the detached Ed25519
/// signature over those bytes, hex-encoded). Pipeline:
///
/// 1. Load the configured signing public key. Not configured -> 400.
/// 2. Read both parts; a missing part -> 400.
/// 3. Verify the signature over the binary bytes. Mismatch -> 400 and
///    `lorica_hot_upgrade_total{outcome="signature_failed"}` ticks.
/// 4. Stage the verified binary atomically at
///    `<data_dir>/upgrade/lorica.new` (0755). Success ->
///    `lorica_hot_upgrade_total{outcome="ok"}` ticks and the handler
///    returns `200 {data:{staged_path, size, sha256}}`.
///
/// This chunk STAGES only; the execve / FD-handoff / drain is wired in
/// Story 8.4 chunk 2 at the [`trigger_handoff`] seam.
///
/// Authorization: mounted behind `require_auth`. Story 8.3 RBAC will
/// retag this SuperAdmin-only once role tags land.
pub async fn upgrade_binary(
    Extension(state): Extension<AppState>,
    mut multipart: Multipart,
) -> Result<Json<serde_json::Value>, ApiError> {
    let public_key: Vec<u8> = match load_signing_public_key(&state).await {
        Ok(key) => key,
        Err(UpgradeError::NoSigningKey) => {
            return Err(ApiError::BadRequest(
                "no upgrade signing key configured".to_string(),
            ));
        }
        Err(e) => {
            return Err(ApiError::Internal(format!(
                "upgrade signing key load failed: {e}"
            )));
        }
    };

    let mut binary: Option<Vec<u8>> = None;
    let mut signature_hex: Option<String> = None;
    while let Some(field) = multipart
        .next_field()
        .await
        .map_err(|e| ApiError::BadRequest(format!("malformed multipart upload: {e}")))?
    {
        let name: Option<String> = field.name().map(str::to_string);
        match name.as_deref() {
            Some("binary") => {
                let bytes = field
                    .bytes()
                    .await
                    .map_err(|e| ApiError::BadRequest(format!("failed to read binary part: {e}")))?;
                binary = Some(bytes.to_vec());
            }
            Some("signature") => {
                let text = field.text().await.map_err(|e| {
                    ApiError::BadRequest(format!("failed to read signature part: {e}"))
                })?;
                signature_hex = Some(text);
            }
            _ => {}
        }
    }

    let binary: Vec<u8> =
        binary.ok_or_else(|| ApiError::BadRequest("missing `binary` upload part".to_string()))?;
    let signature_hex: String = signature_hex
        .ok_or_else(|| ApiError::BadRequest("missing `signature` upload part".to_string()))?;
    let signature: Vec<u8> = decode_hex(signature_hex.trim())
        .filter(|s| s.len() == SIGNATURE_LEN)
        .ok_or_else(|| {
            ApiError::BadRequest(
                "malformed detached signature (expected 128 hex chars / 64 bytes)".to_string(),
            )
        })?;

    if let Err(e) = verify_binary_signature(&binary, &signature, &public_key) {
        record_hot_upgrade("signature_failed");
        return Err(ApiError::BadRequest(format!(
            "binary signature verification failed: {e}"
        )));
    }

    let digest = ring::digest::digest(&ring::digest::SHA256, &binary);
    let sha256: String = encode_hex(digest.as_ref());
    let size: u64 = binary.len() as u64;

    let staged_path: PathBuf = stage_binary(&state.data_dir, &binary)
        .map_err(|e| ApiError::Internal(format!("failed to stage uploaded binary: {e}")))?;

    record_hot_upgrade("ok");

    // Stage succeeded: signal the supervisor to begin the zero-downtime
    // handoff (fork the staged binary, pass listening sockets, drain).
    // The "ok" outcome above records a successful verify+stage; the
    // handoff's own terminal outcome ("exec_failed" / "drain_timeout" on
    // rollback) is recorded by the supervisor. Signalling AFTER building
    // the success response below would race the supervisor's drain
    // against this task being torn down, so we signal here and return.
    trigger_handoff(&state, &staged_path).await;

    Ok(json_data(serde_json::json!({
        "staged_path": staged_path.display().to_string(),
        "size": size,
        "sha256": sha256,
    })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{Signer, SigningKey};

    fn signing_key(seed: u8) -> SigningKey {
        SigningKey::from_bytes(&[seed; 32])
    }

    #[test]
    fn verify_good_signature_ok() {
        let key = signing_key(1);
        let binary = b"the next lorica release binary";
        let sig = key.sign(binary);
        let result = verify_binary_signature(binary, &sig.to_bytes(), key.verifying_key().as_bytes());
        assert!(result.is_ok(), "a valid signature must verify: {result:?}");
    }

    #[test]
    fn verify_tampered_binary_fails() {
        let key = signing_key(2);
        let binary = b"original binary bytes";
        let sig = key.sign(binary);
        let tampered = b"original binary bytez";
        let err = verify_binary_signature(tampered, &sig.to_bytes(), key.verifying_key().as_bytes())
            .expect_err("a tampered binary must not verify");
        assert!(matches!(err, UpgradeError::SignatureMismatch));
    }

    #[test]
    fn verify_wrong_key_fails() {
        let signer = signing_key(3);
        let other = signing_key(4);
        let binary = b"binary signed by signer";
        let sig = signer.sign(binary);
        let err = verify_binary_signature(binary, &sig.to_bytes(), other.verifying_key().as_bytes())
            .expect_err("a signature from a different key must not verify");
        assert!(matches!(err, UpgradeError::SignatureMismatch));
    }

    #[test]
    fn verify_malformed_key_length_errors_cleanly() {
        let key = signing_key(5);
        let binary = b"some binary";
        let sig = key.sign(binary);
        // 31-byte key: wrong length, must error rather than panic.
        let short_key = vec![0u8; PUBLIC_KEY_LEN - 1];
        let err = verify_binary_signature(binary, &sig.to_bytes(), &short_key)
            .expect_err("a wrong-length public key must error");
        assert!(matches!(err, UpgradeError::BadPublicKey));
    }

    #[test]
    fn verify_malformed_signature_length_errors_cleanly() {
        let key = signing_key(6);
        let binary = b"some binary";
        // 10-byte signature: wrong length, must error rather than panic.
        let short_sig = vec![0u8; 10];
        let err = verify_binary_signature(binary, &short_sig, key.verifying_key().as_bytes())
            .expect_err("a wrong-length signature must error");
        assert!(matches!(err, UpgradeError::BadSignature));
    }

    #[test]
    fn decode_hex_round_trips() {
        let bytes = [0xde, 0xad, 0xbe, 0xef];
        let hex = encode_hex(&bytes);
        assert_eq!(hex, "deadbeef");
        assert_eq!(decode_hex(&hex), Some(bytes.to_vec()));
    }

    #[test]
    fn decode_hex_rejects_odd_length_and_non_hex() {
        assert_eq!(decode_hex("abc"), None);
        assert_eq!(decode_hex("zz"), None);
    }

    #[test]
    fn decode_public_key_hex_enforces_length() {
        let valid = encode_hex(&[0x11; PUBLIC_KEY_LEN]);
        assert!(decode_public_key_hex(&valid).is_ok());
        let too_short = encode_hex(&[0x11; PUBLIC_KEY_LEN - 1]);
        assert!(matches!(
            decode_public_key_hex(&too_short),
            Err(UpgradeError::BadPublicKey)
        ));
    }

    #[test]
    fn stage_binary_writes_executable_and_is_atomic() {
        let dir = tempfile::tempdir().expect("test tempdir");
        let payload = b"#!/bin/sh\necho lorica\n";
        let staged = stage_binary(dir.path(), payload).expect("staging must succeed");
        assert_eq!(
            staged,
            dir.path().join("upgrade").join(STAGED_BINARY_NAME)
        );
        let written = std::fs::read(&staged).expect("staged file must be readable");
        assert_eq!(written, payload);
        let mode = std::fs::metadata(&staged)
            .expect("staged file metadata")
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o755, "staged binary must be 0755");
        // No leftover temp file after the rename.
        assert!(!dir
            .path()
            .join("upgrade")
            .join(STAGED_BINARY_TMP_NAME)
            .exists());
    }
}
