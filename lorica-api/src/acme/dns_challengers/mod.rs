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

//! DNS-01 challenge provider trait and built-in implementations.

use serde::{Deserialize, Serialize};

mod cloudflare;
mod ovh;
#[cfg(feature = "route53")]
mod route53;

pub use cloudflare::CloudflareDnsChallenger;
pub use ovh::OvhDnsChallenger;
#[cfg(feature = "route53")]
pub use route53::Route53DnsChallenger;

/// Configuration for DNS-01 ACME challenges.
#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct DnsChallengeConfig {
    /// DNS provider: `"cloudflare"`, `"route53"`, or `"ovh"`.
    pub provider: String,
    /// Zone identifier (Cloudflare zone ID or Route53 hosted zone ID).
    /// Not used for OVH (zone is extracted from domain).
    #[serde(default)]
    pub zone_id: String,
    /// API token (Cloudflare API token or AWS access key ID).
    /// For OVH: the application_key.
    #[serde(default)]
    pub api_token: String,
    /// Optional secret (AWS secret access key, OVH application_secret).
    pub api_secret: Option<String>,
    /// OVH endpoint (default: "eu.api.ovh.com"). Only used for OVH.
    #[serde(default)]
    pub ovh_endpoint: Option<String>,
    /// OVH consumer key. Only used for OVH.
    #[serde(default)]
    pub ovh_consumer_key: Option<String>,
}

impl DnsChallengeConfig {
    /// Validate the configuration and return an error message if invalid.
    pub fn validate(&self) -> Result<(), String> {
        match self.provider.as_str() {
            "cloudflare" => {
                if self.zone_id.is_empty() {
                    return Err("zone_id is required".into());
                }
                if self.api_token.is_empty() {
                    return Err("api_token is required".into());
                }
            }
            "route53" => {
                if self.zone_id.is_empty() {
                    return Err("zone_id is required".into());
                }
                if self.api_token.is_empty() {
                    return Err("api_token is required".into());
                }
                if self.api_secret.as_ref().is_none_or(|s| s.is_empty()) {
                    return Err("api_secret is required for route53 provider".into());
                }
            }
            "ovh" => {
                if self.api_token.is_empty() {
                    return Err("api_token (application_key) is required for OVH".into());
                }
                if self.api_secret.as_ref().is_none_or(|s| s.is_empty()) {
                    return Err("api_secret (application_secret) is required for OVH".into());
                }
                if self.ovh_consumer_key.as_ref().is_none_or(|s| s.is_empty()) {
                    return Err("ovh_consumer_key is required for OVH".into());
                }
            }
            other => {
                return Err(format!(
                    "unsupported DNS provider '{}': expected 'cloudflare', 'route53', or 'ovh'",
                    other
                ));
            }
        }
        Ok(())
    }
}

/// Trait for DNS providers that can create and delete ACME challenge TXT records.
#[async_trait::async_trait]
pub trait DnsChallenger: Send + Sync {
    /// Create a TXT record at `_acme-challenge.{domain}` with the given value.
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), String>;
    /// Delete the TXT record at `_acme-challenge.{domain}`.
    async fn delete_txt_record(&self, domain: &str) -> Result<(), String>;
}

/// Build a `DnsChallenger` from a `DnsChallengeConfig`.
pub async fn build_dns_challenger(
    config: &DnsChallengeConfig,
) -> Result<Box<dyn DnsChallenger>, String> {
    config.validate()?;
    match config.provider.as_str() {
        "cloudflare" => Ok(Box::new(CloudflareDnsChallenger::new(
            config.zone_id.clone(),
            config.api_token.clone(),
        ))),
        #[cfg(feature = "route53")]
        "route53" => Ok(Box::new(
            Route53DnsChallenger::new(
                config.zone_id.clone(),
                config.api_token.clone(),
                config
                    .api_secret
                    .clone()
                    .expect("validate() ensures api_secret is Some for route53"),
            )
            .await,
        )),
        #[cfg(not(feature = "route53"))]
        "route53" => Err("route53 provider requires the 'route53' feature flag".into()),
        "ovh" => Ok(Box::new(OvhDnsChallenger::new(
            config
                .ovh_endpoint
                .clone()
                .unwrap_or_else(|| "eu.api.ovh.com".to_string()),
            config.api_token.clone(),
            config
                .api_secret
                .clone()
                .expect("validate() ensures api_secret is Some for ovh"),
            config
                .ovh_consumer_key
                .clone()
                .expect("validate() ensures ovh_consumer_key is Some for ovh"),
        ))),
        other => Err(format!("unsupported DNS provider: {other}")),
    }
}
