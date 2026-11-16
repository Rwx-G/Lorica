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

//! What a TCP stream's connection cap declares to the fd budget (Story
//! 12.3 D-p).
//!
//! `max_connections` is a per-node cap, counted exactly on the stream's
//! caps region (Story 12.6 D-f). The fd budget is per process and one
//! worker may still hold the whole cap, so each process declares
//! `max_connections` as its ceiling.

use lorica_config::models::{Stream, StreamProtocol};

use crate::budget::HeldFds;

/// Fds one TCP stream connection holds: the client socket and one
/// backend socket (the connect phase holds at most one at a time).
pub const TCP_FDS_PER_CONNECTION: u64 = 2;

/// What a TCP stream may hold at its cap, for the fd budget: the one
/// definition, read through [`crate::StreamDemand::of`], which both the
/// driver's demand and the API's budget check build on, so they cannot
/// disagree. `None` for a UDP stream (Story 12.5 declares its own).
pub fn held_fds(stream: &Stream) -> Option<HeldFds> {
    match stream.protocol {
        StreamProtocol::Tcp => Some(HeldFds {
            ceiling: u64::from(stream.max_connections),
            fds_per_unit: TCP_FDS_PER_CONNECTION,
        }),
        StreamProtocol::Udp => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn a_tcp_stream_holds_two_fds_per_connection() {
        let mut tcp = Stream::new(
            "s".into(),
            "s".into(),
            StreamProtocol::Tcp,
            "0.0.0.0".parse().unwrap(),
            5432,
            5432,
            Utc::now(),
        );
        tcp.max_connections = 100;
        assert_eq!(
            held_fds(&tcp),
            Some(HeldFds {
                ceiling: 100,
                fds_per_unit: 2
            })
        );
        let udp = Stream::new(
            "u".into(),
            "u".into(),
            StreamProtocol::Udp,
            "0.0.0.0".parse().unwrap(),
            53,
            53,
            Utc::now(),
        );
        assert_eq!(held_fds(&udp), None);
    }
}
