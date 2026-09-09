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

//! What an established operational session knows about itself: the
//! contract Story 9.3 (identity, fencing) and Story 9.4 (dispatch)
//! consume, kept apart from the listener that produces it.

use std::net::SocketAddr;

use crate::roster::NodeIdentity;

/// Everything known about an established operational session; the
/// per-session log context, and the handler input for Stories 9.3
/// (identity, fencing) and 9.4 (dispatch).
#[derive(Debug, Clone)]
pub struct SessionContext {
    /// The peer's transport address.
    pub peer_addr: SocketAddr,
    /// Lowercase-hex SHA-256 of the peer's leaf certificate DER - the
    /// identity Story 9.3 records at enrollment and matches here.
    /// `None` only if the TLS layer exposed no chain (it always does
    /// on the operational path, where client auth is mandatory).
    pub peer_cert_fingerprint: Option<String>,
    /// The protocol version both sides agreed on (AC #4).
    pub negotiated_version: u32,
    /// The supervisor takeover epoch this session was accepted under
    /// (Story 9.1 AC #7; the registry fences older epochs).
    pub takeover_epoch: u64,
    /// The enrolled node behind the certificate (Story 9.3 AC #8),
    /// `None` only when the listener runs without a fleet layer.
    pub node: Option<NodeIdentity>,
}

impl SessionContext {
    /// First 16 hex characters of the fingerprint for log lines, or
    /// `-` when absent.
    pub fn fingerprint_prefix(&self) -> &str {
        self.peer_cert_fingerprint
            .as_deref()
            .map(|fp| &fp[..fp.len().min(16)])
            .unwrap_or("-")
    }

    /// The node id from the certificate identity, when resolved.
    pub fn node_id(&self) -> Option<&str> {
        self.node.as_ref().map(|n| n.node_id.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fingerprint_prefix_is_bounded_and_tolerates_absence() {
        let mut ctx = SessionContext {
            peer_addr: "192.0.2.10:9444".parse().expect("addr"),
            peer_cert_fingerprint: Some("ab".repeat(32)),
            negotiated_version: 1,
            takeover_epoch: 0,
            node: None,
        };
        assert_eq!(ctx.fingerprint_prefix(), "abababababababab");
        assert!(ctx.node_id().is_none());
        ctx.peer_cert_fingerprint = Some("abc".to_string());
        assert_eq!(ctx.fingerprint_prefix(), "abc");
        ctx.peer_cert_fingerprint = None;
        assert_eq!(ctx.fingerprint_prefix(), "-");
    }
}
