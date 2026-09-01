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

//! Error type for the pure ACME core.

use thiserror::Error;

/// Error returned by the ACME protocol driver and its supporting helpers.
///
/// This type is self-contained: it never references any management-plane
/// error (`lorica-api`'s `ApiError`). The caller maps it onto its own
/// error type at the boundary. Each variant's `Display` embeds the
/// originating library message verbatim so downstream classifiers (for
/// example a Let's Encrypt rate-limit detector matching on `"too many
/// certificates"`) keep working across the wrap.
#[derive(Debug, Error)]
pub enum AcmeError {
    /// ACME account creation or restoration failed.
    #[error("ACME account error: {0}")]
    Account(String),

    /// ACME order creation, restoration, or authorization walk failed.
    #[error("ACME order error: {0}")]
    Order(String),

    /// No challenge of the required type was offered for an authorization.
    /// The inner value is the challenge type name (`"HTTP-01"` / `"DNS-01"`).
    #[error("no {0} challenge available")]
    NoChallenge(&'static str),

    /// A DNS provider rejected a TXT record create or delete.
    #[error("DNS challenge error: {0}")]
    DnsChallenge(String),

    /// The order did not reach the `Ready` state after challenge validation.
    #[error("challenge validation did not reach Ready: {0}")]
    NotReady(String),

    /// CSR generation (rcgen) failed.
    #[error("CSR generation failed: {0}")]
    Csr(String),

    /// Certificate finalization or polling failed.
    #[error("certificate poll failed: {0}")]
    CertificatePoll(String),

    /// Serialization or deserialization of ACME account credentials failed.
    #[error("credentials error: {0}")]
    Credentials(String),

    /// The HTTP-01 challenge solver failed to publish a token
    /// (Story 9.1 AC #9). Raised BEFORE the driver signals readiness,
    /// so a partial distribution aborts the order instead of racing
    /// an opaque CA validation failure.
    #[error("HTTP-01 challenge solver failed: {0}")]
    Solver(String),
}
