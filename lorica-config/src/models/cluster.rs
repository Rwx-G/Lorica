//! Cluster registry models (Story 9.3): enrolled nodes, join tokens,
//! this node's own identity, and the revocation list source.

use std::str::FromStr;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// Lifecycle state of an enrolled node (Story 9.3 AC #5/#9).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeStatus {
    /// Enrolled, holding a certificate, receiving no configuration and
    /// no certificates until a SuperAdmin activates it.
    Pending,
    /// Full fleet member.
    Active,
    /// Certificate on the CRL; refused at the TLS handshake.
    Revoked,
}

impl NodeStatus {
    /// Canonical `snake_case` identifier (the database value).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Active => "active",
            Self::Revoked => "revoked",
        }
    }
}

impl FromStr for NodeStatus {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "pending" => Ok(Self::Pending),
            "active" => Ok(Self::Active),
            "revoked" => Ok(Self::Revoked),
            other => Err(format!("unknown node status: {other}")),
        }
    }
}

/// One row of `cluster_nodes` (Story 9.3 AC #9), the control plane's
/// registry of enrolled followers.
#[derive(Debug, Clone, Serialize)]
pub struct ClusterNode {
    /// Server-assigned UUID; the identity every label and audit entry
    /// uses.
    pub node_id: String,
    /// Display name (token-bound or chosen at join); never an
    /// authorization input.
    pub name: String,
    /// Lowercase-hex SHA-256 of the node's current certificate DER.
    pub cert_fingerprint: String,
    /// Uppercase-hex serial of the current certificate (CRLs revoke
    /// by serial).
    pub cert_serial: String,
    /// Fingerprint of the certificate a renewal superseded, still
    /// accepted until the node's first session on the new one.
    pub prev_cert_fingerprint: Option<String>,
    /// Serial of that superseded certificate.
    pub prev_cert_serial: Option<String>,
    /// Last observed transport address (`ip:port`).
    pub address: String,
    /// Last reported build version.
    pub version: String,
    /// Last reported database schema version.
    pub schema_version: i64,
    /// Lifecycle state.
    pub status: NodeStatus,
    /// When the token was redeemed.
    pub enrolled_at: DateTime<Utc>,
    /// Last heartbeat or session event persisted by the flush task.
    pub last_seen_at: Option<DateTime<Utc>>,
    /// Configuration generation the node last reported applying
    /// (Story 9.4).
    pub applied_config_generation: i64,
    /// Canonical hash of that applied configuration (Story 9.4).
    pub applied_config_hash: String,
    /// `notAfter` of the current certificate.
    pub cert_not_after: DateTime<Utc>,
    /// When the node was revoked, if it was.
    pub revoked_at: Option<DateTime<Utc>>,
}

/// Lifecycle state of a join token (Story 9.3 AC #4).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenState {
    /// Minted, not yet redeemed (live while unexpired).
    Unused,
    /// Redeemed by exactly one node.
    Burned,
    /// Withdrawn by an operator before redemption.
    Revoked,
}

impl TokenState {
    /// Canonical `snake_case` identifier (the database value).
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Unused => "unused",
            Self::Burned => "burned",
            Self::Revoked => "revoked",
        }
    }
}

impl FromStr for TokenState {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unused" => Ok(Self::Unused),
            "burned" => Ok(Self::Burned),
            "revoked" => Ok(Self::Revoked),
            other => Err(format!("unknown token state: {other}")),
        }
    }
}

/// One row of `cluster_join_tokens` (Story 9.3 AC #1/#5). The secret
/// itself is never stored; `secret_hmac` is its HMAC-SHA256 under the
/// control plane's token key, and it never serializes.
#[derive(Debug, Clone, Serialize)]
pub struct JoinToken {
    /// The indexed lookup half of the token.
    pub public_id: String,
    /// Lowercase-hex HMAC-SHA256 of the secret half. Never serialized.
    #[serde(skip)]
    pub secret_hmac: String,
    /// Lifecycle state.
    pub state: TokenState,
    /// When it was minted.
    pub created_at: DateTime<Utc>,
    /// After this instant the token cannot be redeemed.
    pub expires_at: DateTime<Utc>,
    /// Username of the operator who minted it.
    pub created_by: String,
    /// When set, the redeeming node must present exactly this name.
    pub bound_node_name: Option<String>,
    /// When set, the redeeming connection must come from this CIDR.
    pub bound_source_cidr: Option<String>,
    /// When it was redeemed.
    pub burned_at: Option<DateTime<Utc>>,
    /// The node that redeemed it.
    pub burned_by_node_id: Option<String>,
}

impl JoinToken {
    /// Whether the token can still be redeemed at `now`: unused and
    /// unexpired. The enrollment listener exists only while at least
    /// one token is live.
    pub fn is_live(&self, now: DateTime<Utc>) -> bool {
        self.state == TokenState::Unused && self.expires_at > now
    }
}

/// This node's own fleet identity (a follower's single
/// `cluster_identity` row, Story 9.3 AC #3/#12). The private key is
/// encrypted at rest under the node's master key.
#[derive(Debug, Clone)]
pub struct ClusterIdentity {
    /// The server-assigned node id.
    pub node_id: String,
    /// The display name registered at enrollment.
    pub node_name: String,
    /// The `clientAuth` leaf, PEM.
    pub cert_pem: String,
    /// The leaf's private key, PEM (never leaves the node).
    pub key_pem: String,
    /// The cluster CA bundle received at enrollment (the only trust
    /// root the dialer verifies against).
    pub ca_pem: String,
    /// The control plane's `host:port`, resolved on every dial.
    pub control_plane: String,
    /// The name the control-plane certificate must verify as.
    pub server_name: String,
    /// When the identity was granted.
    pub enrolled_at: DateTime<Utc>,
    /// `notAfter` of the current leaf; renewal fires at two thirds of
    /// the lifetime.
    pub cert_not_after: DateTime<Utc>,
}

/// One revoked certificate serial (Story 9.3 AC #7), the source the
/// CRL is minted from: node revocations and superseded renewals both
/// land here.
#[derive(Debug, Clone, Serialize)]
pub struct RevokedSerial {
    /// Uppercase-hex certificate serial.
    pub serial: String,
    /// When the control plane processed the revocation.
    pub revoked_at: DateTime<Utc>,
    /// `revoked` (operator action) or `superseded` (renewal).
    pub reason: String,
    /// `notAfter` of the revoked certificate: past it the serial is
    /// pruned, a CRL never needs an expired certificate.
    pub expires_at: DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn status_and_state_round_trip() {
        for status in [NodeStatus::Pending, NodeStatus::Active, NodeStatus::Revoked] {
            assert_eq!(status.as_str().parse::<NodeStatus>(), Ok(status));
        }
        for state in [TokenState::Unused, TokenState::Burned, TokenState::Revoked] {
            assert_eq!(state.as_str().parse::<TokenState>(), Ok(state));
        }
        assert!("gone".parse::<NodeStatus>().is_err());
        assert!("gone".parse::<TokenState>().is_err());
    }

    #[test]
    fn a_token_is_live_only_while_unused_and_unexpired() {
        let now = Utc::now();
        let mut token = JoinToken {
            public_id: "p".to_string(),
            secret_hmac: "h".to_string(),
            state: TokenState::Unused,
            created_at: now,
            expires_at: now + chrono::Duration::hours(1),
            created_by: "admin".to_string(),
            bound_node_name: None,
            bound_source_cidr: None,
            burned_at: None,
            burned_by_node_id: None,
        };
        assert!(token.is_live(now));
        assert!(!token.is_live(now + chrono::Duration::hours(2)));
        token.state = TokenState::Burned;
        assert!(!token.is_live(now));
        // The HMAC never serializes.
        let json = serde_json::to_string(&token).expect("serialize");
        assert!(!json.contains("secret_hmac"));
    }
}
