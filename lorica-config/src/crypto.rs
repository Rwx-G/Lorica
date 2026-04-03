use std::path::Path;

use ring::aead::{self, Aad, BoundKey, Nonce, NonceSequence, OpeningKey, SealingKey, UnboundKey};
use ring::rand::{SecureRandom, SystemRandom};

use crate::error::{ConfigError, Result};

const KEY_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;

/// A 256-bit AES-GCM encryption key for protecting sensitive data at rest.
#[derive(Clone)]
pub struct EncryptionKey {
    raw: [u8; KEY_LEN],
}

impl EncryptionKey {
    /// Create an encryption key from raw bytes.
    pub fn from_bytes(bytes: [u8; KEY_LEN]) -> Self {
        Self { raw: bytes }
    }

    /// Generate a new random encryption key.
    pub fn generate() -> Result<Self> {
        let rng = SystemRandom::new();
        let mut raw = [0u8; KEY_LEN];
        rng.fill(&mut raw)
            .map_err(|_| ConfigError::Validation("failed to generate random key".into()))?;
        Ok(Self { raw })
    }

    /// Load an encryption key from a file, or generate and save a new one.
    pub fn load_or_create(path: &Path) -> Result<Self> {
        if path.exists() {
            let bytes = std::fs::read(path)?;
            if bytes.len() != KEY_LEN {
                return Err(ConfigError::Validation(format!(
                    "encryption key file has wrong size: expected {KEY_LEN}, got {}",
                    bytes.len()
                )));
            }
            let mut raw = [0u8; KEY_LEN];
            raw.copy_from_slice(&bytes);
            tracing::info!("loaded encryption key from {}", path.display());
            Ok(Self { raw })
        } else {
            let key = Self::generate()?;
            std::fs::write(path, key.raw)?;
            // Restrict permissions to owner-only (0600)
            #[cfg(unix)]
            {
                use std::os::unix::fs::PermissionsExt;
                let _ = std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600));
            }
            tracing::info!("generated new encryption key at {}", path.display());
            Ok(key)
        }
    }

    /// Encrypt plaintext using AES-256-GCM. Returns nonce || ciphertext || tag.
    pub fn encrypt(&self, plaintext: &[u8]) -> Result<Vec<u8>> {
        let rng = SystemRandom::new();
        let mut nonce_bytes = [0u8; NONCE_LEN];
        rng.fill(&mut nonce_bytes)
            .map_err(|_| ConfigError::Validation("failed to generate nonce".into()))?;

        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &self.raw)
            .map_err(|_| ConfigError::Validation("invalid encryption key".into()))?;
        let mut sealing_key = SealingKey::new(unbound_key, SingleNonce::new(nonce_bytes));

        let mut in_out = plaintext.to_vec();
        sealing_key
            .seal_in_place_append_tag(Aad::empty(), &mut in_out)
            .map_err(|_| ConfigError::Validation("encryption failed".into()))?;

        // Output format: nonce (12 bytes) || ciphertext+tag
        let mut output = Vec::with_capacity(NONCE_LEN + in_out.len());
        output.extend_from_slice(&nonce_bytes);
        output.extend_from_slice(&in_out);
        Ok(output)
    }

    /// Decrypt data produced by `encrypt`. Expects nonce || ciphertext || tag.
    pub fn decrypt(&self, encrypted: &[u8]) -> Result<Vec<u8>> {
        if encrypted.len() < NONCE_LEN + TAG_LEN {
            return Err(ConfigError::Validation("encrypted data too short".into()));
        }

        let (nonce_bytes, ciphertext_and_tag) = encrypted.split_at(NONCE_LEN);
        let mut nonce_arr = [0u8; NONCE_LEN];
        nonce_arr.copy_from_slice(nonce_bytes);

        let unbound_key = UnboundKey::new(&aead::AES_256_GCM, &self.raw)
            .map_err(|_| ConfigError::Validation("invalid encryption key".into()))?;
        let mut opening_key = OpeningKey::new(unbound_key, SingleNonce::new(nonce_arr));

        let mut in_out = ciphertext_and_tag.to_vec();
        let plaintext = opening_key
            .open_in_place(Aad::empty(), &mut in_out)
            .map_err(|_| ConfigError::Validation("decryption failed".into()))?;
        Ok(plaintext.to_vec())
    }
}

/// A NonceSequence that yields a single nonce then fails.
struct SingleNonce {
    nonce: Option<[u8; NONCE_LEN]>,
}

impl SingleNonce {
    fn new(nonce: [u8; NONCE_LEN]) -> Self {
        Self { nonce: Some(nonce) }
    }
}

impl NonceSequence for SingleNonce {
    fn advance(&mut self) -> std::result::Result<Nonce, ring::error::Unspecified> {
        self.nonce
            .take()
            .map(Nonce::assume_unique_for_key)
            .ok_or(ring::error::Unspecified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_decrypt_round_trip() {
        let key = EncryptionKey::generate().unwrap();
        let plaintext = b"-----BEGIN PRIVATE KEY-----\ntest data\n-----END PRIVATE KEY-----";
        let encrypted = key.encrypt(plaintext).unwrap();

        assert_ne!(encrypted, plaintext);
        assert!(encrypted.len() > plaintext.len());

        let decrypted = key.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, plaintext);
    }

    #[test]
    fn test_different_nonces() {
        let key = EncryptionKey::generate().unwrap();
        let plaintext = b"same data";
        let enc1 = key.encrypt(plaintext).unwrap();
        let enc2 = key.encrypt(plaintext).unwrap();
        // Different nonces produce different ciphertext
        assert_ne!(enc1, enc2);
        // But both decrypt to the same plaintext
        assert_eq!(key.decrypt(&enc1).unwrap(), plaintext);
        assert_eq!(key.decrypt(&enc2).unwrap(), plaintext);
    }

    #[test]
    fn test_wrong_key_fails() {
        let key1 = EncryptionKey::generate().unwrap();
        let key2 = EncryptionKey::generate().unwrap();
        let encrypted = key1.encrypt(b"secret").unwrap();
        assert!(key2.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_corrupted_data_fails() {
        let key = EncryptionKey::generate().unwrap();
        let mut encrypted = key.encrypt(b"data").unwrap();
        // Flip a byte in the ciphertext
        let last = encrypted.len() - 1;
        encrypted[last] ^= 0xFF;
        assert!(key.decrypt(&encrypted).is_err());
    }

    #[test]
    fn test_too_short_data_fails() {
        let key = EncryptionKey::generate().unwrap();
        assert!(key.decrypt(&[0u8; 10]).is_err());
    }

    #[test]
    fn test_key_load_or_create() {
        let tmp = tempfile::NamedTempFile::new().unwrap();
        let path = tmp.path().with_extension("key");

        // First call creates the key
        let key1 = EncryptionKey::load_or_create(&path).unwrap();
        // Second call loads the same key
        let key2 = EncryptionKey::load_or_create(&path).unwrap();

        // Verify they produce compatible encryption
        let encrypted = key1.encrypt(b"test").unwrap();
        let decrypted = key2.decrypt(&encrypted).unwrap();
        assert_eq!(decrypted, b"test");

        std::fs::remove_file(&path).ok();
    }
}
