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

//! The rules a CES endpoint and a service principal must meet. The
//! client applies them before it connects; the API applies the same
//! functions when an authority is saved, so a value that would fail at
//! the first operation is refused at the write instead.

use reqwest::Url;

use crate::krb5conf::Realm;
use crate::AdcsError;

fn invalid(reason: String) -> AdcsError {
    AdcsError::InvalidParams { reason }
}

/// A CES endpoint: an `https://` URL without credentials whose host is a
/// DNS name, since the service ticket is for `HTTP/<host>`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CesEndpoint {
    url: Url,
    host: String,
}

impl CesEndpoint {
    /// Validates `value` as a CES endpoint. Nothing is trimmed.
    ///
    /// ```
    /// let endpoint = lorica_adcs::CesEndpoint::new(
    ///     "https://ces.corp.example.org/CA_CES_Kerberos/service.svc/CES",
    /// )?;
    /// assert_eq!(endpoint.host(), "ces.corp.example.org");
    /// assert!(lorica_adcs::CesEndpoint::new("http://ces.corp.example.org/CES").is_err());
    /// # Ok::<(), lorica_adcs::AdcsError>(())
    /// ```
    pub fn new(value: &str) -> Result<CesEndpoint, AdcsError> {
        let url: Url = Url::parse(value)
            .map_err(|err| invalid(format!("the endpoint {value:?} is not a URL: {err}")))?;
        if url.scheme() != "https" {
            return Err(invalid(format!(
                "the endpoint must be https://, not {}://",
                url.scheme()
            )));
        }
        if !url.username().is_empty() || url.password().is_some() {
            return Err(invalid(
                "the endpoint must not carry credentials in the URL".to_owned(),
            ));
        }
        let host: String = url
            .domain()
            .ok_or_else(|| {
                invalid(format!(
                    "the endpoint host of {value:?} must be a DNS name: the service ticket is for \
                     HTTP/<host>"
                ))
            })?
            .to_owned();
        Ok(CesEndpoint { url, host })
    }

    /// The URL as parsed.
    pub fn url(&self) -> &Url {
        &self.url
    }

    /// The host the service ticket is asked for.
    pub fn host(&self) -> &str {
        &self.host
    }
}

/// The service account as a Kerberos principal, `user@REALM`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Principal(String);

impl Principal {
    /// Validates `value`, `user` or `user@REALM` with `realm`, and
    /// completes the first form with the realm. Nothing is trimmed.
    ///
    /// ```
    /// let realm = lorica_adcs::Realm::new("CORP.EXAMPLE.ORG")?;
    /// let principal = lorica_adcs::Principal::new("svc-lorica", &realm)?;
    /// assert_eq!(principal.as_str(), "svc-lorica@CORP.EXAMPLE.ORG");
    /// assert!(lorica_adcs::Principal::new("svc@OTHER.EXAMPLE.ORG", &realm).is_err());
    /// # Ok::<(), lorica_adcs::AdcsError>(())
    /// ```
    pub fn new(value: &str, realm: &Realm) -> Result<Principal, AdcsError> {
        if value.is_empty()
            || value
                .chars()
                .any(|c: char| c.is_control() || c.is_whitespace())
        {
            return Err(invalid(format!(
                "the principal {value:?} is empty or contains spaces or control characters"
            )));
        }
        match value.split_once('@') {
            None => Ok(Principal(format!("{value}@{realm}"))),
            Some((user, principal_realm))
                if !user.is_empty() && principal_realm == realm.as_str() =>
            {
                Ok(Principal(value.to_owned()))
            }
            Some(_) => Err(invalid(format!(
                "the principal {value:?} must be a user name or user@{realm}"
            ))),
        }
    }

    /// `user@REALM`.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn realm() -> Realm {
        Realm::new("CORP.EXAMPLE.ORG").expect("realm")
    }

    #[test]
    fn a_principal_with_its_realm_is_kept() {
        for value in ["svc-lorica@CORP.EXAMPLE.ORG", "svc-lorica"] {
            assert_eq!(
                Principal::new(value, &realm()).expect("principal").as_str(),
                "svc-lorica@CORP.EXAMPLE.ORG"
            );
        }
    }

    #[test]
    fn principals_outside_the_rules_are_refused() {
        for value in [
            "",
            "svc lorica",
            "svc\tlorica",
            "svc@OTHER.EXAMPLE.ORG",
            "@CORP.EXAMPLE.ORG",
            " svc-lorica",
        ] {
            assert!(
                matches!(
                    Principal::new(value, &realm()),
                    Err(AdcsError::InvalidParams { .. })
                ),
                "{value:?}"
            );
        }
    }

    #[test]
    fn endpoints_outside_the_rules_are_refused() {
        for value in [
            "http://ces.corp.example.org/CES",
            "https://192.0.2.10/CES",
            "https://[2001:db8::1]/CES",
            "https://user:secret@ces.corp.example.org/CES",
            "https://user@ces.corp.example.org/CES",
            "not a url",
            "",
        ] {
            assert!(
                matches!(
                    CesEndpoint::new(value),
                    Err(AdcsError::InvalidParams { .. })
                ),
                "{value:?}"
            );
        }
        let endpoint: CesEndpoint =
            CesEndpoint::new("https://ces.corp.example.org:8443/CES").expect("endpoint");
        assert_eq!(endpoint.host(), "ces.corp.example.org");
        assert_eq!(endpoint.url().port(), Some(8443));
    }
}
