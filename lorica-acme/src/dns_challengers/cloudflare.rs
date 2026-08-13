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

//! Cloudflare DNS-01 challenger using the Cloudflare API v4.

use std::time::Duration;

use tracing::info;

use super::DnsChallenger;

/// Per-request timeout for the Cloudflare API client (v1.5.1
/// audit L-7). Pre-fix, the client was built with
/// `reqwest::Client::new()` which has no timeout set ; a hung
/// Cloudflare API endpoint could hold the ACME flow open
/// indefinitely. Cloudflare's documented SLO targets sub-second
/// API responses, so 30 s is well above the worst-case healthy
/// response while still bounding a stuck call.
const CLOUDFLARE_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// Default Cloudflare API v4 base URL. Swapped in tests via
/// `with_base_url` to point at a `wiremock` mock server.
const CLOUDFLARE_API_V4: &str = "https://api.cloudflare.com/client/v4";

/// Cloudflare DNS-01 challenger using the Cloudflare API v4.
pub struct CloudflareDnsChallenger {
    zone_id: String,
    api_token: String,
    base_url: String,
    client: reqwest::Client,
}

impl CloudflareDnsChallenger {
    /// Construct a new challenger bound to a Cloudflare zone and API token,
    /// targeting the public Cloudflare API.
    pub fn new(zone_id: String, api_token: String) -> Self {
        Self::with_base_url(zone_id, api_token, CLOUDFLARE_API_V4.to_string())
    }

    /// Construct a challenger with a custom API base URL. `pub(crate)` so
    /// unit tests in `acme::tests` can point the challenger at a
    /// `wiremock::MockServer` instance.
    pub(crate) fn with_base_url(zone_id: String, api_token: String, base_url: String) -> Self {
        let client = reqwest::Client::builder()
            .timeout(CLOUDFLARE_HTTP_TIMEOUT)
            .build()
            .expect("reqwest::Client builder with a static timeout is infallible");
        Self {
            zone_id,
            api_token,
            base_url,
            client,
        }
    }

    /// Find the record ID for a given TXT record name.
    async fn find_record_id(&self, name: &str) -> Result<Option<String>, String> {
        let url = format!(
            "{}/zones/{}/dns_records?type=TXT&name={}",
            self.base_url, self.zone_id, name
        );
        let resp = self
            .client
            .get(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .header("Content-Type", "application/json")
            .send()
            .await
            .map_err(|e| format!("Cloudflare API request failed: {e}"))?;

        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("Cloudflare API response parse error: {e}"))?;

        if let Some(results) = body.get("result").and_then(|r| r.as_array()) {
            if let Some(record) = results.first() {
                if let Some(id) = record.get("id").and_then(|v| v.as_str()) {
                    return Ok(Some(id.to_string()));
                }
            }
        }
        Ok(None)
    }
}

#[async_trait::async_trait]
impl DnsChallenger for CloudflareDnsChallenger {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), String> {
        let record_name = format!("_acme-challenge.{domain}");
        let url = format!("{}/zones/{}/dns_records", self.base_url, self.zone_id);

        let payload = serde_json::json!({
            "type": "TXT",
            "name": record_name,
            "content": value,
            "ttl": 120,
        });

        let resp = self
            .client
            .post(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .header("Content-Type", "application/json")
            .json(&payload)
            .send()
            .await
            .map_err(|e| format!("Cloudflare create TXT record failed: {e}"))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp
                .text()
                .await
                .unwrap_or_else(|e| format!("<failed to read response body: {e}>"));
            return Err(format!("Cloudflare API returned {status}: {body}"));
        }

        info!(domain = %domain, record = %record_name, "Cloudflare DNS TXT record created");
        Ok(())
    }

    async fn delete_txt_record(&self, domain: &str) -> Result<(), String> {
        let record_name = format!("_acme-challenge.{domain}");
        let record_id = self
            .find_record_id(&record_name)
            .await?
            .ok_or_else(|| format!("TXT record '{record_name}' not found for deletion"))?;

        let url = format!(
            "{}/zones/{}/dns_records/{record_id}",
            self.base_url, self.zone_id
        );

        let resp = self
            .client
            .delete(&url)
            .header("Authorization", format!("Bearer {}", self.api_token))
            .send()
            .await
            .map_err(|e| format!("Cloudflare delete TXT record failed: {e}"))?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp
                .text()
                .await
                .unwrap_or_else(|e| format!("<failed to read response body: {e}>"));
            return Err(format!("Cloudflare API delete returned {status}: {body}"));
        }

        info!(domain = %domain, record = %record_name, "Cloudflare DNS TXT record deleted");
        Ok(())
    }
}
