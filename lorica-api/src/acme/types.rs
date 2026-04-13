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

//! Shared DTOs and pending-challenge state for the ACME flows.

use std::sync::Arc;
use std::time::Instant;

use dashmap::DashMap;
use serde::Serialize;

/// In-memory store for pending manual DNS-01 challenges.
///
/// Maps domain name to the pending challenge state. Entries are created by
/// `provision_dns_manual` (step 1) and consumed by `provision_dns_manual_confirm`
/// (step 2). Entries older than 10 minutes are considered expired.
pub type PendingDnsChallenges = Arc<DashMap<String, PendingDnsChallenge>>;

/// State for a pending manual DNS-01 challenge between the two-step flow.
#[derive(Clone)]
pub struct PendingDnsChallenge {
    /// The order URL so we can restore the order from the ACME account.
    pub order_url: String,
    /// The challenge URLs to mark as ready (one per domain).
    pub challenge_urls: Vec<String>,
    /// The TXT record entries the user must create: (record_name, txt_value, domain).
    pub txt_records: Vec<(String, String, String)>,
    /// All domains in this order.
    pub domains: Vec<String>,
    /// Serialized account credentials (JSON) to restore the ACME account.
    pub account_credentials_json: String,
    /// Whether this was issued against the staging directory.
    pub staging: bool,
    /// Contact email used for the ACME account.
    pub contact_email: Option<String>,
    /// When this pending challenge was created (for expiry).
    pub created_at: Instant,
}

/// Response body common to all ACME provisioning endpoints.
#[derive(Debug, Serialize)]
pub(super) struct AcmeProvisionResponse {
    pub(super) status: String,
    pub(super) domain: String,
    pub(super) staging: bool,
    pub(super) message: String,
}

/// Serde default helper: default value for the `staging` flag is `true`.
pub(super) fn default_true() -> bool {
    true
}
