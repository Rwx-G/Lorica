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

//! ACME / Let's Encrypt integration for automatic TLS certificate provisioning.
//!
//! Supports three challenge modes:
//! - **HTTP-01**: Requires port 80 reachable from the Internet.
//! - **DNS-01 (automated)**: Creates a `_acme-challenge.{domain}` TXT record via DNS
//!   provider API. Supports Cloudflare and AWS Route53.
//! - **DNS-01 (manual)**: Returns the TXT record info for the user to create manually,
//!   then confirms the challenge in a second step.
//!
//! This module is organised into focused submodules:
//! - [`store`]: the SQLite-backed challenge token store shared across workers.
//! - [`config`]: the `AcmeConfig` describing the Let's Encrypt directory.
//! - [`types`]: request/response DTOs and pending challenge state.
//! - [`http01`]: HTTP-01 provisioning endpoints and internal flow.
//! - [`renewal`]: background renewal task and manual renewal endpoint.
//! - [`expiry`]: certificate expiry check task (alerts).
//! - [`dns_challengers`]: `DnsChallenger` trait and provider implementations.
//! - [`dns01`]: automated DNS-01 provisioning endpoint and internal flow.
//! - [`dns01_manual`]: two-step manual DNS-01 flow (init, check, confirm).

mod config;
mod dns01;
mod dns01_manual;
pub mod dns_challengers;
mod expiry;
mod http01;
mod renewal;
mod store;
mod types;

#[cfg(test)]
mod tests;

pub use config::AcmeConfig;
pub use dns01::{provision_certificate_dns, AcmeDnsProvisionRequest};
pub use dns01_manual::{
    check_dns_manual, provision_dns_manual, provision_dns_manual_confirm,
    AcmeDnsManualConfirmRequest, AcmeDnsManualRequest,
};
#[cfg(feature = "route53")]
pub use dns_challengers::Route53DnsChallenger;
pub use dns_challengers::{
    build_dns_challenger, CloudflareDnsChallenger, DnsChallengeConfig, DnsChallenger,
    OvhDnsChallenger,
};
pub use expiry::{check_cert_expiry, spawn_cert_expiry_check_task};
pub use http01::{provision_certificate, serve_challenge, AcmeProvisionRequest};
pub use renewal::{renew_certificate, spawn_renewal_task};
pub use store::AcmeChallengeStore;
pub use types::{PendingDnsChallenge, PendingDnsChallenges};
