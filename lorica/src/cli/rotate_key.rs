// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0

//! `lorica rotate-key` subcommand : re-encrypt every stored secret
//! under a new symmetric key.
//!
//! Reads the existing key from `<data-dir>/encryption.key`, loads the
//! new key from `--new-key-file` (creating one if the path does not
//! exist), opens the SQLite store under the old key, rewrites every
//! encrypted column under the new key, and prints the operator-facing
//! "now move this file there" instructions for the manual cutover.

use std::path::PathBuf;

use lorica_config::crypto::EncryptionKey;
use lorica_config::store::ConfigStore;

/// Run the `rotate-key` subcommand.
///
/// `data_dir` is the resolved `--data-dir` (CLI flag or default).
/// `new_key_file` is the resolved `--new-key-file` argument.
pub fn run(data_dir: &str, new_key_file: &str) {
    let data_dir = PathBuf::from(data_dir);
    let key_path = data_dir.join("encryption.key");
    let old_key = EncryptionKey::load_or_create(&key_path)
        .expect("failed to load current encryption key");

    let new_key_path = PathBuf::from(new_key_file);
    let new_key = EncryptionKey::load_or_create(&new_key_path)
        .expect("failed to load/create new encryption key");

    let db_path = data_dir.join("lorica.db");
    let store = ConfigStore::open(&db_path, Some(old_key)).expect("failed to open database");

    let count = store
        .rotate_encryption_key(&new_key)
        .expect("key rotation failed");

    println!("Key rotation complete: {count} secrets re-encrypted");
    println!(
        "IMPORTANT: Replace {} with {}",
        key_path.display(),
        new_key_path.display()
    );
    println!("  mv {} {}.backup", key_path.display(), key_path.display());
    println!("  mv {} {}", new_key_path.display(), key_path.display());
}
