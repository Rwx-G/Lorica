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

//! OVH DNS-01 challenger using the OVH API.

use std::time::Duration;

use tracing::info;

use super::DnsChallenger;

/// Per-request timeout for the OVH API client (v1.5.1 audit L-7).
/// Pre-fix, the client was built with `reqwest::Client::new()`
/// which has no timeout set ; a hung OVH endpoint could hold the
/// ACME flow open indefinitely. OVH's API is typically sub-
/// second on healthy paths, so 30 s is well above worst-case
/// healthy response while still bounding a stuck call. The
/// challenger's own DNS-propagation wait loop has its own
/// bigger timeout - this only bounds the per-call HTTP work.
const OVH_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// OVH DNS-01 challenger using the OVH API.
///
/// OVH authentication uses application_key, application_secret and consumer_key.
/// Each request is signed with a SHA1 hash of the concatenation:
/// `application_secret+consumer_key+METHOD+URL+BODY+timestamp`.
pub struct OvhDnsChallenger {
    /// Full URL prefix including scheme and API version suffix (e.g.
    /// `"https://eu.api.ovh.com/1.0"`). Tests swap this for a mock
    /// server origin like `"http://127.0.0.1:xxxx/1.0"`.
    base_url: String,
    application_key: String,
    application_secret: String,
    consumer_key: String,
    client: reqwest::Client,
    /// Track created record IDs for cleanup (domain -> record_id).
    created_records: parking_lot::Mutex<std::collections::HashMap<String, u64>>,
}

impl OvhDnsChallenger {
    /// Construct a new OVH challenger from the four-part credential set.
    /// `endpoint` is the bare host (e.g. `"eu.api.ovh.com"`) ; the
    /// `https://{endpoint}/1.0` prefix is computed internally.
    pub fn new(
        endpoint: String,
        application_key: String,
        application_secret: String,
        consumer_key: String,
    ) -> Self {
        Self::with_base_url(
            format!("https://{endpoint}/1.0"),
            application_key,
            application_secret,
            consumer_key,
        )
    }

    /// Construct a challenger with a fully-qualified API base URL. `pub(crate)`
    /// so unit tests in `acme::tests` can point the challenger at a
    /// `wiremock::MockServer` instance (where the scheme is `http://` and the
    /// host carries a random port).
    pub(crate) fn with_base_url(
        base_url: String,
        application_key: String,
        application_secret: String,
        consumer_key: String,
    ) -> Self {
        let client = reqwest::Client::builder()
            .timeout(OVH_HTTP_TIMEOUT)
            .build()
            .expect("reqwest::Client builder with a static timeout is infallible");
        Self {
            base_url,
            application_key,
            application_secret,
            consumer_key,
            client,
            created_records: parking_lot::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Extract zone and subdomain from a domain name.
    /// e.g. "bastion.rwx-g.fr" -> zone="rwx-g.fr", subdomain="_acme-challenge.bastion"
    /// e.g. "rwx-g.fr" -> zone="rwx-g.fr", subdomain="_acme-challenge"
    pub(crate) fn extract_zone_and_subdomain(domain: &str) -> (String, String) {
        let parts: Vec<&str> = domain.split('.').collect();
        if parts.len() <= 2 {
            // domain is the zone itself (e.g. "rwx-g.fr")
            (domain.to_string(), "_acme-challenge".to_string())
        } else {
            // zone is the last 2 parts, subdomain is the rest prefixed with _acme-challenge
            let zone = format!("{}.{}", parts[parts.len() - 2], parts[parts.len() - 1]);
            let sub_parts = &parts[..parts.len() - 2];
            let subdomain = format!("_acme-challenge.{}", sub_parts.join("."));
            (zone, subdomain)
        }
    }

    /// Get the OVH server timestamp for request signing.
    async fn get_server_time(&self) -> Result<i64, String> {
        let url = format!("{}/auth/time", self.base_url);
        let resp = self
            .client
            .get(&url)
            .send()
            .await
            .map_err(|e| format!("OVH get server time failed: {e}"))?;
        let time: i64 = resp
            .json()
            .await
            .map_err(|e| format!("OVH server time parse failed: {e}"))?;
        Ok(time)
    }

    /// Compute the OVH API signature.
    /// Format: "$1$" + SHA1(application_secret+"+"+consumer_key+"+"+method+"+"+url+"+"+body+"+"+timestamp)
    fn sign(&self, method: &str, url: &str, body: &str, timestamp: i64) -> String {
        let to_sign = format!(
            "{}+{}+{}+{}+{}+{}",
            self.application_secret, self.consumer_key, method, url, body, timestamp
        );
        let digest =
            ring::digest::digest(&ring::digest::SHA1_FOR_LEGACY_USE_ONLY, to_sign.as_bytes());
        let hex: String = digest.as_ref().iter().map(|b| format!("{b:02x}")).collect();
        format!("$1${hex}")
    }

    /// Make a signed request to the OVH API.
    async fn ovh_request(
        &self,
        method: reqwest::Method,
        path: &str,
        body: Option<&serde_json::Value>,
    ) -> Result<reqwest::Response, String> {
        let url = format!("{}{}", self.base_url, path);
        let body_str = match body {
            Some(b) => serde_json::to_string(b)
                .map_err(|e| format!("OVH: failed to serialize request body: {e}"))?,
            None => String::new(),
        };
        let timestamp = self.get_server_time().await?;
        let signature = self.sign(method.as_str(), &url, &body_str, timestamp);

        let mut req = self
            .client
            .request(method, &url)
            .header("X-Ovh-Application", &self.application_key)
            .header("X-Ovh-Timestamp", timestamp.to_string())
            .header("X-Ovh-Consumer", &self.consumer_key)
            .header("X-Ovh-Signature", &signature)
            .header("Content-Type", "application/json");

        if !body_str.is_empty() {
            req = req.body(body_str);
        }

        req.send()
            .await
            .map_err(|e| format!("OVH API request failed: {e}"))
    }

    /// Refresh the DNS zone to apply changes.
    async fn refresh_zone(&self, zone: &str) -> Result<(), String> {
        let path = format!("/domain/zone/{zone}/refresh");
        let resp = self.ovh_request(reqwest::Method::POST, &path, None).await?;
        let status = resp.status();
        if !status.is_success() {
            let body = resp
                .text()
                .await
                .unwrap_or_else(|e| format!("<failed to read response body: {e}>"));
            return Err(format!("OVH zone refresh returned {status}: {body}"));
        }
        Ok(())
    }
}

#[async_trait::async_trait]
impl DnsChallenger for OvhDnsChallenger {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), String> {
        let (zone, subdomain) = Self::extract_zone_and_subdomain(domain);

        let payload = serde_json::json!({
            "fieldType": "TXT",
            "subDomain": subdomain,
            "target": value,
            "ttl": 60
        });

        let path = format!("/domain/zone/{zone}/record");
        let resp = self
            .ovh_request(reqwest::Method::POST, &path, Some(&payload))
            .await?;

        let status = resp.status();
        let body: serde_json::Value = resp
            .json()
            .await
            .map_err(|e| format!("OVH create TXT response parse error: {e}"))?;

        if !status.is_success() {
            return Err(format!("OVH create TXT returned {status}: {body}"));
        }

        // Store record ID for later deletion
        if let Some(id) = body.get("id").and_then(|v| v.as_u64()) {
            self.created_records.lock().insert(domain.to_string(), id);
        }

        // Refresh zone to apply changes
        self.refresh_zone(&zone).await?;

        info!(domain = %domain, zone = %zone, subdomain = %subdomain, "OVH DNS TXT record created");
        Ok(())
    }

    async fn delete_txt_record(&self, domain: &str) -> Result<(), String> {
        let (zone, _subdomain) = Self::extract_zone_and_subdomain(domain);

        let record_id = self
            .created_records
            .lock()
            .remove(domain)
            .ok_or_else(|| format!("no tracked OVH record ID for domain '{domain}'"))?;

        let path = format!("/domain/zone/{zone}/record/{record_id}");
        let resp = self
            .ovh_request(reqwest::Method::DELETE, &path, None)
            .await?;

        let status = resp.status();
        if !status.is_success() {
            let body = resp
                .text()
                .await
                .unwrap_or_else(|e| format!("<failed to read response body: {e}>"));
            return Err(format!("OVH delete TXT returned {status}: {body}"));
        }

        // Refresh zone to apply changes
        self.refresh_zone(&zone).await?;

        info!(domain = %domain, "OVH DNS TXT record deleted");
        Ok(())
    }
}
