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

//! The service account password, held so that its buffer is zeroed when
//! it is dropped (Story 13.1 AC #2).
//!
//! `zeroize` was not approved as a dependency (Story 13.1, "The password
//! buffer is wiped without `zeroize`"), so the wipe is the same technique
//! done here: volatile writes, which the optimiser may not remove, then a
//! compiler fence so no later access is reordered before them. Copies
//! made by `libgssapi` and MIT krb5 during acquisition are outside the
//! crate's reach and are not claimed to be wiped.

use std::fmt;
use std::sync::atomic::{compiler_fence, Ordering};

/// A password whose bytes are overwritten with zeros when it is dropped.
///
/// It has no `Display`, and its `Debug` prints `Secret(<redacted>)`, so
/// formatting a structure that holds one never prints the password.
///
/// ```
/// let password = lorica_adcs::Secret::new(String::from("example-only"));
/// assert_eq!(password.expose(|text: &str| text.len()), 12);
/// assert_eq!(format!("{password:?}"), "Secret(<redacted>)");
/// ```
pub struct Secret {
    text: String,
}

impl Secret {
    /// Takes ownership of `text`, so the only buffer holding it from now
    /// on is the one this value wipes.
    pub fn new(text: String) -> Secret {
        Secret { text }
    }

    /// Lends the password to `use_it` for the duration of the call. The
    /// closure form keeps the borrow short and visible at the call site.
    pub fn expose<R>(&self, use_it: impl FnOnce(&str) -> R) -> R {
        use_it(&self.text)
    }
}

impl From<String> for Secret {
    fn from(text: String) -> Secret {
        Secret::new(text)
    }
}

// A copy is needed to move the password into a blocking GSS-API task,
// which must own what it uses; the copy is a `Secret` and is wiped too.
impl Clone for Secret {
    fn clone(&self) -> Secret {
        Secret::new(self.text.clone())
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(<redacted>)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        // `into_bytes` hands over the same allocation without copying.
        // Growing the length to the capacity, which never reallocates,
        // brings bytes left behind by an earlier truncation into the
        // wiped range as well.
        let mut bytes: Vec<u8> = std::mem::take(&mut self.text).into_bytes();
        let capacity: usize = bytes.capacity();
        bytes.resize(capacity, 0);
        wipe(&mut bytes);
    }
}

/// Overwrites every byte of `buffer` with zero in a way the compiler
/// keeps even though the buffer is about to be freed.
#[allow(unsafe_code)] // A volatile write the optimiser cannot drop; see SAFETY below.
pub(crate) fn wipe(buffer: &mut [u8]) {
    for byte in buffer.iter_mut() {
        // SAFETY: `byte` comes from a live `&mut [u8]`, so it is non-null,
        // aligned, valid for a one-byte write and not aliased for the
        // duration of the write; the write stays inside that slice.
        unsafe { std::ptr::write_volatile(byte, 0) };
    }
    compiler_fence(Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wipe_zeroes_every_byte() {
        let mut buffer: Vec<u8> = b"correct horse battery staple".to_vec();
        wipe(&mut buffer);
        assert!(!buffer.is_empty());
        assert!(buffer.iter().all(|byte: &u8| *byte == 0));
    }

    #[test]
    fn expose_lends_the_text_and_debug_redacts_it() {
        let secret: Secret = Secret::new("example-only-password".to_owned());
        assert_eq!(secret.expose(str::to_owned), "example-only-password");
        let shown: String = format!("{secret:?} {:?}", secret.clone());
        assert!(!shown.contains("example-only"), "{shown}");
    }
}
