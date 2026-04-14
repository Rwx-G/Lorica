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

//! SipHash-1-3 for the shmem hashtable probe chain.
//!
//! Used with a 128-bit key randomized once by the supervisor at startup
//! (see [`crate::region::SharedRegion::hash_key`]). A secret key prevents
//! attackers from crafting IP addresses that collide into the same probe
//! chain and saturate `MAX_PROBE`. See design doc § 5.3.
//!
//! SipHash-1-3 has 1 compression round and 3 finalization rounds; it is
//! the "fast" variant of SipHash used for hashtable lookups by the Rust
//! standard library since 1.31.

/// Compute SipHash-1-3 of a single 8-byte input using the supplied 128-bit
/// key. Equivalent to hashing the little-endian byte representation of
/// `input` as an 8-byte message.
#[inline]
pub fn siphash13_u64(key: [u64; 2], input: u64) -> u64 {
    let k0 = key[0];
    let k1 = key[1];

    let mut v0: u64 = k0 ^ 0x736f_6d65_7073_6575;
    let mut v1: u64 = k1 ^ 0x646f_7261_6e64_6f6d;
    let mut v2: u64 = k0 ^ 0x6c79_6765_6e65_7261;
    let mut v3: u64 = k1 ^ 0x7465_6462_7974_6573;

    // Single 8-byte message block.
    v3 ^= input;
    siphash_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= input;

    // Final length-carrying block: message length is 8 bytes, so the final
    // block is `(len & 0xff) << 56` with no low-order message bytes.
    let finalblock: u64 = 8u64 << 56;
    v3 ^= finalblock;
    siphash_round(&mut v0, &mut v1, &mut v2, &mut v3);
    v0 ^= finalblock;

    // Finalization: 3 rounds, then XOR the state.
    v2 ^= 0xff;
    siphash_round(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash_round(&mut v0, &mut v1, &mut v2, &mut v3);
    siphash_round(&mut v0, &mut v1, &mut v2, &mut v3);

    v0 ^ v1 ^ v2 ^ v3
}

#[inline(always)]
fn siphash_round(v0: &mut u64, v1: &mut u64, v2: &mut u64, v3: &mut u64) {
    *v0 = v0.wrapping_add(*v1);
    *v1 = v1.rotate_left(13);
    *v1 ^= *v0;
    *v0 = v0.rotate_left(32);

    *v2 = v2.wrapping_add(*v3);
    *v3 = v3.rotate_left(16);
    *v3 ^= *v2;

    *v0 = v0.wrapping_add(*v3);
    *v3 = v3.rotate_left(21);
    *v3 ^= *v0;

    *v2 = v2.wrapping_add(*v1);
    *v1 = v1.rotate_left(17);
    *v1 ^= *v2;
    *v2 = v2.rotate_left(32);
}

/// Generate a fresh random 128-bit key using OS-backed entropy.
pub fn random_key() -> [u64; 2] {
    use rand::RngCore;
    let mut rng = rand::rngs::OsRng;
    let mut bytes = [0u8; 16];
    rng.fill_bytes(&mut bytes);
    let k0 = u64::from_le_bytes(bytes[..8].try_into().expect("8 bytes"));
    let k1 = u64::from_le_bytes(bytes[8..].try_into().expect("8 bytes"));
    [k0, k1]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deterministic_for_same_key_and_input() {
        let key = [0x1111_2222_3333_4444, 0x5555_6666_7777_8888];
        let h1 = siphash13_u64(key, 0xdead_beef_cafe_babe);
        let h2 = siphash13_u64(key, 0xdead_beef_cafe_babe);
        assert_eq!(h1, h2);
    }

    #[test]
    fn differs_when_key_changes() {
        let h1 = siphash13_u64([1, 2], 42);
        let h2 = siphash13_u64([3, 4], 42);
        assert_ne!(h1, h2);
    }

    #[test]
    fn differs_when_input_changes() {
        let key = [1, 2];
        let h1 = siphash13_u64(key, 42);
        let h2 = siphash13_u64(key, 43);
        assert_ne!(h1, h2);
    }

    #[test]
    fn zero_input_with_zero_key_is_not_zero() {
        // Sanity: the finalization and constants avoid a trivial all-zero
        // output for all-zero input.
        let h = siphash13_u64([0, 0], 0);
        assert_ne!(h, 0);
    }

    #[test]
    fn random_keys_differ() {
        let k1 = random_key();
        let k2 = random_key();
        // Astronomically improbable to collide on 128 bits.
        assert_ne!(k1, k2);
    }

    #[test]
    fn distribution_sanity() {
        // Hash 10_000 sequential u64s; distinct outputs, no trivial bias
        // in low bits (approximately half of slot-bit parities should be
        // 1 when bucketed into 128K slots).
        let key = random_key();
        let n = 10_000usize;
        let mut buckets_low = [0u32; 4];
        for i in 0..n {
            let h = siphash13_u64(key, i as u64);
            buckets_low[(h & 3) as usize] += 1;
        }
        // Each bucket should hold ~2500. Allow a generous ±15% tolerance.
        for c in &buckets_low {
            assert!(
                (*c as i64 - 2500).abs() < 400,
                "low-bit bucket imbalance: {:?}",
                buckets_low
            );
        }
    }
}
