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

//! Cluster protocol version negotiation (Story 9.2 AC #4).
//!
//! Ranges, not exact equality: with exact-version refusal there is no
//! order in which to upgrade a fleet, because a control plane and a
//! follower one patch apart could never talk. Each side advertises the
//! [minimum, maximum] protocol versions it speaks and the session runs
//! at the highest version both ranges contain.

/// Highest cluster protocol version this build speaks.
pub const PROTOCOL_VERSION: u32 = 1;

/// Lowest cluster protocol version this build still accepts. Raising
/// this is a fleet-wide compatibility event: every node below it must
/// be upgraded FIRST.
pub const PROTOCOL_MIN_COMPATIBLE: u32 = 1;

/// Negotiate the session protocol version: the highest version inside
/// both inclusive ranges, or `None` when the ranges do not overlap
/// (map that to `ClusterStatus::IncompatibleVersion` on the
/// operational path, and to the opaque status pre-auth).
pub fn negotiate(
    local_min: u32,
    local_max: u32,
    peer_min: u32,
    peer_max: u32,
) -> Option<u32> {
    // Guard inverted ranges (a malformed Hello): treat as no overlap.
    if local_min > local_max || peer_min > peer_max {
        return None;
    }
    let low: u32 = local_min.max(peer_min);
    let high: u32 = local_max.min(peer_max);
    (low <= high).then_some(high)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn equal_ranges_negotiate_their_max() {
        assert_eq!(negotiate(1, 1, 1, 1), Some(1));
        assert_eq!(negotiate(1, 3, 1, 3), Some(3));
    }

    #[test]
    fn rolling_upgrade_one_version_apart_still_talks() {
        // Control plane upgraded to v2 first (still accepts v1),
        // follower still v1-only: the session runs at 1.
        assert_eq!(negotiate(1, 2, 1, 1), Some(1));
        // Follower upgraded first: symmetric.
        assert_eq!(negotiate(1, 1, 1, 2), Some(1));
    }

    #[test]
    fn overlap_picks_the_highest_common_version() {
        assert_eq!(negotiate(1, 3, 2, 5), Some(3));
        assert_eq!(negotiate(2, 5, 1, 3), Some(3));
    }

    #[test]
    fn disjoint_ranges_refuse() {
        // Fleet-wide min raised before every node upgraded: the
        // leftover node is refused, not silently mis-spoken to.
        assert_eq!(negotiate(3, 4, 1, 2), None);
        assert_eq!(negotiate(1, 2, 3, 4), None);
    }

    #[test]
    fn inverted_ranges_refuse() {
        assert_eq!(negotiate(2, 1, 1, 1), None);
        assert_eq!(negotiate(1, 1, 5, 2), None);
    }

    // Compile-time invariant: the advertised range must be well
    // formed or every negotiation would refuse.
    const _: () = assert!(PROTOCOL_MIN_COMPATIBLE <= PROTOCOL_VERSION);

    #[test]
    fn build_constants_are_a_valid_range() {
        assert_eq!(
            negotiate(
                PROTOCOL_MIN_COMPATIBLE,
                PROTOCOL_VERSION,
                PROTOCOL_MIN_COMPATIBLE,
                PROTOCOL_VERSION
            ),
            Some(PROTOCOL_VERSION)
        );
    }
}
