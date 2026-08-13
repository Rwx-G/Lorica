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

#![deny(unsafe_code)]
#![warn(missing_docs)]

//! Pure ACME / Let's Encrypt protocol core for Lorica.
//!
//! This crate holds the parts of certificate provisioning that have no
//! business depending on the management API: the `instant-acme` protocol
//! driver, CSR generation, and the DNS-01 provider challengers. None of it
//! touches a configuration store, an audit log, or any management-plane
//! state. The `lorica-api` handlers call into here for the pure core and
//! keep all axum / database / audit plumbing to themselves.
//!
//! The three issuance entry points live in [`driver`]:
//! - [`issue_http01`] drives an order using the HTTP-01 challenge.
//! - [`issue_dns01`] drives an order using the automated DNS-01 challenge.
//! - [`begin_manual_dns01`] / [`finalize_manual_dns01`] drive the two-step
//!   manual DNS-01 flow.
//!
//! DNS providers implement [`DnsChallenger`]; built-ins cover Cloudflare,
//! OVH, and (behind the `route53` feature) AWS Route53.

pub mod config;
pub mod dns_challengers;
pub mod driver;
pub mod error;

#[cfg(test)]
mod tests;

pub use config::AcmeConfig;
#[cfg(feature = "route53")]
pub use dns_challengers::Route53DnsChallenger;
pub use dns_challengers::{
    build_dns_challenger, CloudflareDnsChallenger, DnsChallengeConfig, DnsChallenger,
    OvhDnsChallenger,
};
pub use driver::{
    acme_dns_base_domain, begin_manual_dns01, finalize_manual_dns01, issue_dns01, issue_http01,
    Http01ChallengeSolver, IssuedCertificate, ManualDns01Challenge, ManualDns01Order,
};
pub use error::AcmeError;
