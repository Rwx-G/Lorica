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

//! Aliyun (Alibaba Cloud) DNS-01 challenger using the Alidns OpenAPI.
//!
//! Alidns is an RPC-style API (version `2015-01-09`): every call is an
//! HTTPS `GET` whose query carries the action's parameters plus the
//! common parameters, signed with HMAC-SHA1 over the canonicalised
//! query. The challenger talks to the API directly instead of adding a
//! vendor SDK; three actions cover the flow, so the RAM policy can stay
//! as narrow as for the other providers: `DescribeDomainRecords`,
//! `AddDomainRecord`, `DeleteDomainRecord`.

use std::time::Duration;

use base64::Engine as _;
use ring::rand::SecureRandom as _;
use serde_json::Value;
use tracing::info;

use super::DnsChallenger;

/// Alidns OpenAPI version, sent as the `Version` parameter on every
/// request and covered by its signature.
const ALIYUN_API_VERSION: &str = "2015-01-09";

/// Per-request timeout for the Alidns API client: bounds a hung endpoint
/// so it cannot hold the ACME order open indefinitely.
const ALIYUN_HTTP_TIMEOUT: Duration = Duration::from_secs(30);

/// TTL of the `_acme-challenge` TXT record, in seconds: the smallest
/// value the free edition of Alidns accepts (also its API default), so
/// the record is valid on every edition. The TTL bounds how long a
/// resolver caches the answer; it does not retract the record, which
/// is why cleanup still deletes the created RecordId.
const ALIYUN_RECORD_TTL: u32 = 600;

/// The single public endpoint Alidns publishes. The official SDK
/// resolves every region id, `cn-hangzhou` included, to this one
/// address, so no region parameter goes on the request and no
/// region-to-endpoint table is needed.
const ALIYUN_ENDPOINT: &str = "https://alidns.aliyuncs.com";

/// Aliyun DNS-01 challenger using the Alidns OpenAPI.
///
/// Each instance remembers the record ids it created, so cleanup
/// deletes exactly those and never a TXT record that was already
/// there: one order can carry two authorizations for the same
/// `_acme-challenge` name (a name and its wildcard), and they must not
/// delete each other. The records are published and retracted
/// serially by [`crate::driver::issue_dns01`]; the bookkeeping assumes
/// that order.
pub struct AliyunDnsChallenger {
    access_key_id: String,
    access_key_secret: String,
    /// Endpoint without a trailing slash. Tests swap it for a
    /// `wiremock::MockServer` origin.
    base_url: String,
    client: reqwest::Client,
    /// Created record ids, keyed by the fully-qualified record name
    /// (`_acme-challenge.<domain>`).
    created_records: parking_lot::Mutex<std::collections::HashMap<String, Vec<String>>>,
}

impl AliyunDnsChallenger {
    /// Construct a new challenger for a RAM user's AccessKey pair,
    /// targeting the public Alidns endpoint.
    ///
    /// # Errors
    ///
    /// The HTTP client cannot be built: the platform trust store offers
    /// certificates and none is usable.
    pub fn new(access_key_id: String, access_key_secret: String) -> Result<Self, String> {
        Self::with_base_url(
            access_key_id,
            access_key_secret,
            ALIYUN_ENDPOINT.to_string(),
        )
    }

    /// Construct a challenger with a custom API base URL. `pub(crate)`
    /// so unit tests in `acme::tests` can point the challenger at a
    /// `wiremock::MockServer` instance.
    pub(crate) fn with_base_url(
        access_key_id: String,
        access_key_secret: String,
        base_url: String,
    ) -> Result<Self, String> {
        let tls = lorica_tls::http_client::public()
            .map_err(|e| format!("Alidns API client trust roots: {e}"))?;
        let client = lorica_tls::http_client::client_builder(tls)
            .timeout(ALIYUN_HTTP_TIMEOUT)
            // The signed query carries the AccessKey id and a reusable
            // signature. A redirect would send them to an endpoint the
            // caller never selected, where both would land in logs.
            .redirect(reqwest::redirect::Policy::none())
            .referer(false)
            .build()
            .map_err(|e| format!("Alidns API client: {e}"))?;
        Ok(Self {
            access_key_id,
            access_key_secret,
            base_url,
            client,
            created_records: parking_lot::Mutex::new(std::collections::HashMap::new()),
        })
    }

    /// The `RR` parameter of the `_acme-challenge` record for `domain`
    /// inside `zone`: the record name minus the zone suffix.
    /// `_acme-challenge` at the zone apex, `_acme-challenge.<prefix>`
    /// below it.
    pub(crate) fn challenge_rr(zone: &str, domain: &str) -> String {
        match domain
            .strip_suffix(zone)
            .and_then(|head| head.strip_suffix('.'))
        {
            Some(prefix) if !prefix.is_empty() => format!("_acme-challenge.{prefix}"),
            _ => "_acme-challenge".to_string(),
        }
    }

    /// Locate the zone that owns `domain`: walk the name's suffixes
    /// from the most specific one up and return the first the account
    /// hosts. `DescribeDomainRecords` answers with an error for a name
    /// the account does not host; only those known "not hosted"
    /// responses move the walk to the next suffix. Credential, RAM and
    /// throttling errors are returned at once rather than disguised as
    /// a missing zone.
    async fn resolve_zone(&self, domain: &str) -> Result<String, String> {
        let mut labels: Vec<&str> = domain.split('.').collect();
        let mut last_err = format!("'{domain}' has no zone suffix to probe");
        while labels.len() >= 2 {
            let candidate = labels.join(".");
            match self
                .rpc(&[
                    ("Action", "DescribeDomainRecords"),
                    ("DomainName", candidate.as_str()),
                    ("PageNumber", "1"),
                    ("PageSize", "1"),
                ])
                .await
            {
                Ok(_) => return Ok(candidate),
                Err(e) if is_zone_probe_miss(&e) => last_err = e,
                Err(e) => return Err(format!("Alidns zone probe failed: {e}")),
            }
            labels.remove(0);
        }
        Err(format!(
            "no hosted Alidns zone found for '{domain}': {last_err}"
        ))
    }

    /// One signed RPC call. `params` are the action's own parameters,
    /// `Action` included; the common parameters (`Version`,
    /// `AccessKeyId`, `SignatureNonce`, `Timestamp`, ...) are added
    /// here. Returns the parsed response body on HTTP success, or the
    /// status with the body's `Code`/`Message` on failure.
    async fn rpc(&self, params: &[(&str, &str)]) -> Result<Value, String> {
        let mut query: Vec<(String, String)> = vec![
            ("Format".to_string(), "JSON".to_string()),
            ("Version".to_string(), ALIYUN_API_VERSION.to_string()),
            ("AccessKeyId".to_string(), self.access_key_id.clone()),
            ("SignatureMethod".to_string(), "HMAC-SHA1".to_string()),
            ("SignatureVersion".to_string(), "1.0".to_string()),
            ("SignatureNonce".to_string(), signature_nonce()?),
            (
                "Timestamp".to_string(),
                chrono::Utc::now().format("%Y-%m-%dT%H:%M:%SZ").to_string(),
            ),
        ];
        query.extend(
            params
                .iter()
                .map(|(k, v)| ((*k).to_string(), (*v).to_string())),
        );

        let canonicalized = canonical_query(&mut query);
        let signature = sign(&self.access_key_secret, &canonicalized);
        let url = format!(
            "{}/?{}&Signature={}",
            self.base_url,
            canonicalized,
            percent_encode(&signature)
        );

        let resp = self
            .client
            .get(&url)
            .send()
            .await
            // `reqwest` includes the full URL in transport errors. The
            // URL carries AccessKeyId and a usable signature; only the
            // failure itself belongs in an ACME log line.
            .map_err(|e| format!("Alidns API request failed: {}", e.without_url()))?;
        let status = resp.status();
        let text = resp
            .text()
            .await
            .map_err(|e| format!("Alidns API response read failed: {}", e.without_url()))?;
        let body: Value = serde_json::from_str(&text).unwrap_or(Value::Null);
        // The gateway can report a business failure in a 200 response.
        // Treat a non-empty `Code` as an error unless it explicitly says
        // the call succeeded.
        let code = body.get("Code").and_then(Value::as_str);
        if !status.is_success() || code.is_some_and(|c| !c.is_empty() && c != "Success") {
            let code = code.unwrap_or("");
            let message = body
                .get("Message")
                .and_then(Value::as_str)
                .unwrap_or(text.as_str());
            let error = format!("Alidns API returned {status}: {code}: {message}");
            return Err(sanitize_error_message(&error));
        }
        if body.is_null() {
            return Err(format!(
                "Alidns API response parse error: invalid JSON in {status} response"
            ));
        }
        Ok(body)
    }
}

#[async_trait::async_trait]
impl DnsChallenger for AliyunDnsChallenger {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), String> {
        let zone = self.resolve_zone(domain).await?;
        let rr = Self::challenge_rr(&zone, domain);
        let ttl = ALIYUN_RECORD_TTL.to_string();

        let body = self
            .rpc(&[
                ("Action", "AddDomainRecord"),
                ("DomainName", zone.as_str()),
                ("RR", rr.as_str()),
                ("Type", "TXT"),
                ("Value", value),
                ("TTL", ttl.as_str()),
            ])
            .await?;

        let record_id = body
            .get("RecordId")
            .and_then(Value::as_str)
            .ok_or("Alidns AddDomainRecord response carries no RecordId")?;
        self.created_records
            .lock()
            .entry(format!("_acme-challenge.{domain}"))
            .or_default()
            .push(record_id.to_string());

        info!(domain = %domain, zone = %zone, rr = %rr, "Alidns TXT record created");
        Ok(())
    }

    async fn delete_txt_record(&self, domain: &str) -> Result<(), String> {
        let record_name = format!("_acme-challenge.{domain}");
        let record_ids = self
            .created_records
            .lock()
            .get(&record_name)
            .cloned()
            .unwrap_or_default();
        if record_ids.is_empty() {
            return Err(format!("no tracked Alidns record ID for '{record_name}'"));
        }

        // Attempt every id: a transient failure on one must not strand
        // the others. Keep failed ids tracked so a later cleanup call
        // can retry them, and remove only those confirmed deleted.
        let mut deleted = Vec::new();
        let mut first_error = None;
        for record_id in &record_ids {
            match self
                .rpc(&[("Action", "DeleteDomainRecord"), ("RecordId", record_id)])
                .await
            {
                Ok(_) => deleted.push(record_id.clone()),
                Err(e) => {
                    if first_error.is_none() {
                        first_error = Some(e);
                    }
                }
            }
        }

        let mut created = self.created_records.lock();
        if let Some(ids) = created.get_mut(&record_name) {
            ids.retain(|id| !deleted.contains(id));
            if ids.is_empty() {
                created.remove(&record_name);
            }
        }
        drop(created);

        if let Some(e) = first_error {
            return Err(e);
        }
        info!(domain = %domain, record = %record_name, "Alidns TXT record deleted");
        Ok(())
    }
}

/// Percent-encode one query component the way the signature algorithm
/// requires: RFC 3986, with the unreserved set (`A-Z a-z 0-9 - _ . ~`)
/// kept verbatim and every other byte written `%HH` in upper-case hex.
/// Upper case is part of the contract: Alidns rejects a signature
/// computed over lower-case escapes. `pub(crate)` for the unit tests.
pub(crate) fn percent_encode(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for &byte in value.as_bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{byte:02X}")),
        }
    }
    out
}

/// The canonicalised query string the signature covers: the parameters
/// ordered by name (every name is unique here), name and value
/// percent-encoded, joined with `&`. `pub(crate)` for the unit tests.
pub(crate) fn canonical_query(params: &mut [(String, String)]) -> String {
    params.sort_by(|a, b| a.0.cmp(&b.0));
    params
        .iter()
        .map(|(k, v)| format!("{}={}", percent_encode(k), percent_encode(v)))
        .collect::<Vec<_>>()
        .join("&")
}

/// Base64 of the HMAC-SHA1 signature over the canonicalised query. The
/// string to sign is `GET&%2F&<encoded query>` and the HMAC key is the
/// AccessKey secret with a trailing `&`, per the Alidns RPC contract.
/// `pub(crate)` for the unit tests.
pub(crate) fn sign(access_key_secret: &str, canonicalized: &str) -> String {
    let string_to_sign = format!("GET&%2F&{}", percent_encode(canonicalized));
    let key = ring::hmac::Key::new(
        ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        format!("{access_key_secret}&").as_bytes(),
    );
    base64::engine::general_purpose::STANDARD
        .encode(ring::hmac::sign(&key, string_to_sign.as_bytes()).as_ref())
}

/// Extract the API `Code` from the error form produced by `rpc()`.
fn api_error_code(error: &str) -> Option<&str> {
    let after_status = error
        .strip_prefix("Alidns API returned ")?
        .split_once(": ")?
        .1;
    after_status.split_once(": ").map(|(code, _)| code)
}

/// Whether an API error says the probed name is not a zone in this
/// account. Only these codes advance the suffix walk: a credential,
/// RAM or throttling failure must surface as itself. Matching the
/// parsed code keeps a code named in a server Message from hiding a
/// real failure.
fn is_zone_probe_miss(error: &str) -> bool {
    matches!(
        api_error_code(error),
        Some(
            "InvalidDomainName.NoExist"
                | "InvalidDomainName.Unregistered"
                | "InvalidDomainName.NotExist"
                | "DomainNotExists"
                | "IncorrectDomainUser"
        )
    )
}

/// Remove signed-query values from a gateway error body. Alidns error
/// bodies normally carry only `Code` and `Message`, but a proxy that
/// echoes the request URL must not turn an error into a replayable
/// signature in the ACME logs.
pub(crate) fn sanitize_error_message(message: &str) -> String {
    let mut scrubbed = message.to_string();
    for parameter in [
        "AccessKeyId=",
        "Signature=",
        "SignatureNonce=",
        "Timestamp=",
    ] {
        let mut search_from = 0;
        while let Some(found) = scrubbed[search_from..].find(parameter) {
            let value_start = search_from + found + parameter.len();
            let value_end = scrubbed[value_start..]
                .find(|c: char| c == '&' || c.is_whitespace() || c == '"' || c == '<')
                .map_or(scrubbed.len(), |offset| value_start + offset);
            scrubbed.replace_range(value_start..value_end, "[REDACTED]");
            search_from = value_start + "[REDACTED]".len();
        }
    }
    scrubbed
}

/// A `SignatureNonce`: 16 random bytes as lower-case hex. A fresh one
/// per request keeps a replayed query from ever validating again.
fn signature_nonce() -> Result<String, String> {
    let mut bytes = [0u8; 16];
    ring::rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|_| "Alidns: failed to draw a signature nonce".to_string())?;
    Ok(bytes.iter().map(|b| format!("{b:02x}")).collect())
}
