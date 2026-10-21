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

//! The few DER encodings the crate writes by hand. A DER writer
//! dependency would be one more crate for a handful of TLVs, and the
//! reading side goes through `x509_parser`'s re-exported parsers.

pub(crate) const TAG_SEQUENCE: u8 = 0x30;
pub(crate) const TAG_SET: u8 = 0x31;
pub(crate) const TAG_BMP_STRING: u8 = 0x1E;

/// One DER TLV with a single-byte tag and a definite length in its
/// shortest form (X.690 10.1).
pub(crate) fn tlv(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(content.len() + 6);
    out.push(tag);
    let len: usize = content.len();
    if len < 0x80 {
        out.push(len as u8);
    } else {
        let len_bytes: [u8; 8] = (len as u64).to_be_bytes();
        let first_significant: usize = len_bytes
            .iter()
            .position(|byte: &u8| *byte != 0)
            .unwrap_or(len_bytes.len() - 1);
        let significant: &[u8] = &len_bytes[first_significant..];
        out.push(0x80 | significant.len() as u8);
        out.extend_from_slice(significant);
    }
    out.extend_from_slice(content);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn short_and_long_lengths_are_minimal() {
        assert_eq!(tlv(0x04, &[]), vec![0x04, 0x00]);
        assert_eq!(tlv(0x04, &[0xAA; 0x7F])[..2], [0x04, 0x7F]);
        assert_eq!(tlv(0x04, &[0xAA; 0x80])[..3], [0x04, 0x81, 0x80]);
        assert_eq!(tlv(0x04, &[0xAA; 0x0100])[..4], [0x04, 0x82, 0x01, 0x00]);
    }
}
