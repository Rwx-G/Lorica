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

//! AWS Route53 DNS-01 challenger using the official AWS SDK.

use tracing::{info, warn};

use super::DnsChallenger;

/// AWS Route53 DNS-01 challenger using the official AWS SDK.
pub struct Route53DnsChallenger {
    hosted_zone_id: String,
    client: aws_sdk_route53::Client,
    /// Track created TXT values so DELETE can provide the exact value.
    created_values: parking_lot::Mutex<std::collections::HashMap<String, String>>,
}

impl Route53DnsChallenger {
    /// Construct a new challenger using AWS credentials and a Route53 hosted zone id.
    pub async fn new(hosted_zone_id: String, access_key: String, secret_key: String) -> Self {
        let creds = aws_sdk_route53::config::Credentials::new(
            access_key,
            secret_key,
            None,
            None,
            "lorica-acme",
        );
        let config = aws_config::defaults(aws_config::BehaviorVersion::latest())
            .region(aws_sdk_route53::config::Region::new("us-east-1"))
            .credentials_provider(creds)
            .load()
            .await;
        let client = aws_sdk_route53::Client::new(&config);
        Self {
            hosted_zone_id,
            client,
            created_values: parking_lot::Mutex::new(std::collections::HashMap::new()),
        }
    }

    async fn change_record(
        &self,
        action: aws_sdk_route53::types::ChangeAction,
        domain: &str,
        value: &str,
    ) -> Result<(), String> {
        use aws_sdk_route53::types::{
            Change, ChangeBatch, ResourceRecord, ResourceRecordSet, RrType,
        };

        let record_name = format!("_acme-challenge.{domain}.");
        let txt_value = format!("\"{value}\"");

        let record_set = ResourceRecordSet::builder()
            .name(&record_name)
            .r#type(RrType::Txt)
            .ttl(120)
            .resource_records(
                ResourceRecord::builder()
                    .value(&txt_value)
                    .build()
                    .map_err(|e| format!("Route53 record build error: {e}"))?,
            )
            .build()
            .map_err(|e| format!("Route53 record set build error: {e}"))?;

        let change = Change::builder()
            .action(action)
            .resource_record_set(record_set)
            .build()
            .map_err(|e| format!("Route53 change build error: {e}"))?;

        let batch = ChangeBatch::builder()
            .changes(change)
            .build()
            .map_err(|e| format!("Route53 batch build error: {e}"))?;

        self.client
            .change_resource_record_sets()
            .hosted_zone_id(&self.hosted_zone_id)
            .change_batch(batch)
            .send()
            .await
            .map_err(|e| format!("Route53 API error: {e}"))?;

        Ok(())
    }
}

#[async_trait::async_trait]
impl DnsChallenger for Route53DnsChallenger {
    async fn create_txt_record(&self, domain: &str, value: &str) -> Result<(), String> {
        self.change_record(aws_sdk_route53::types::ChangeAction::Upsert, domain, value)
            .await?;
        self.created_values
            .lock()
            .insert(domain.to_string(), value.to_string());
        info!(domain = %domain, "Route53 DNS TXT record created");
        Ok(())
    }

    async fn delete_txt_record(&self, domain: &str) -> Result<(), String> {
        let value = match self.created_values.lock().remove(domain) {
            Some(v) => v,
            None => {
                warn!(domain = %domain, "Route53 delete: no tracked value, skipping");
                return Ok(());
            }
        };
        self.change_record(aws_sdk_route53::types::ChangeAction::Delete, domain, &value)
            .await?;
        info!(domain = %domain, "Route53 DNS TXT record deleted");
        Ok(())
    }
}
