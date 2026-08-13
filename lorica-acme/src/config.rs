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

//! ACME account configuration.

/// ACME configuration for the Let's Encrypt directory.
#[derive(Debug, Clone)]
pub struct AcmeConfig {
    /// Use staging directory (recommended for testing).
    pub staging: bool,
    /// Contact email for Let's Encrypt account.
    pub contact_email: Option<String>,
}

impl Default for AcmeConfig {
    fn default() -> Self {
        Self {
            staging: true,
            contact_email: None,
        }
    }
}

impl AcmeConfig {
    /// Return the ACME directory URL (staging or production).
    pub fn directory_url(&self) -> &str {
        if self.staging {
            "https://acme-staging-v02.api.letsencrypt.org/directory"
        } else {
            "https://acme-v02.api.letsencrypt.org/directory"
        }
    }
}
