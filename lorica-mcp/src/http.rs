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

//! The HTTPS implementation of [`crate::AutomationPlane`]: the client
//! the stdio binary reaches the Story 10.3 automation listener with.
//!
//! # Verification is not optional and there is no switch that says so
//!
//! The listener's default certificate is self-signed, and an operator
//! who replaced it has as likely as not signed it with an internal CA.
//! The way that usually ends is a client with an "insecure" flag that
//! somebody sets once to get going and never unsets, at which point the
//! bearer token travels to whoever answered the connection. So there is
//! no such flag here. [`crate::config::CA_BUNDLE_ENV`] names a PEM file
//! of authorities to trust IN ADDITION to the platform store and the
//! built-in public roots, which covers the self-signed certificate (add
//! the certificate itself) and the internal CA (add the CA) without
//! anything being turned off.
//!
//! # AC #6, and what this client can honestly claim
//!
//! Every tool call is to be audited with the token's `public_id`, the
//! tool name, the redacted arguments and a marker saying the transport
//! was MCP. Over stdio that cannot be wholly true and this code does not
//! pretend otherwise. This server is a separate process and reaches the
//! plane over HTTP; the plane audits the HTTP request it receives, and
//! at that layer there is no tool, because a tool is a concept of the
//! protocol this process speaks and not of the one it speaks over.
//!
//! So the split is: the token's `public_id` is ESTABLISHED, by the node
//! verifying the credential, and it is what anchors the row. The tool
//! name and the transport are ASSERTED, by this client, in
//! [`ASSERTED_TOOL_HEADER`] and [`ASSERTED_TRANSPORT_HEADER`], and the
//! plane records them as the caller's claim and labels them as such.
//! The arguments are audited by the plane as the NAMES of the query
//! parameters used and never their values, which is Story 9.9's rule
//! and is the redaction AC #6 asks for.
//!
//! An audit trail that cannot tell a claim from a proof is telling a
//! story that is not true, which is the same reasoning Epic 11 gives
//! for distinguishing a model from a person in the first place.

use std::path::Path;
use std::time::Duration;

use reqwest::header::{HeaderMap, HeaderValue, ACCEPT, AUTHORIZATION, CONTENT_TYPE, USER_AGENT};

use crate::config::ServerConfig;
use crate::{AutomationPlane, PlaneError, Reason, Verb, MAX_ANSWER_BYTES};

/// The header this client declares the tool name in.
///
/// `lorica-` prefixed and with `asserted` in the name itself, so the
/// one place the value is read is not free to forget what it is. There
/// is no `X-`: RFC 6648 deprecated the convention and Lorica's own
/// headers follow it.
pub const ASSERTED_TOOL_HEADER: &str = "lorica-asserted-tool";

/// The header this client declares the transport in.
pub const ASSERTED_TRANSPORT_HEADER: &str = "lorica-asserted-transport";

/// What [`ASSERTED_TRANSPORT_HEADER`] carries from this binding.
///
/// Every MCP binding's marker starts with `mcp`, and the suffix names
/// which one: the Streamable HTTP binding, `lorica-api`'s
/// `automation::mcp`, asserts `mcp-streamable-http`. An operator filtering the trail for anything
/// a model drove matches the prefix; one asking which door it came
/// through reads the whole word.
pub const TRANSPORT_MARKER: &str = "mcp-stdio";

/// How long one read may take end to end.
///
/// A read is a single `GET` against a node that answers from its own
/// store, so a request still running after this is a network that
/// stopped rather than a query that is slow. The model on the other
/// side is waiting, and a client that hangs is worse for it than one
/// that says the plane could not be reached.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// How long one write may take end to end.
///
/// Longer than a read for one call: a certificate renewal is an ACME
/// order the node makes while the request is open, and an HTTP-01 or
/// DNS-01 validation takes the authority's time and not the node's.
/// The timeout matters more than it looks, because a request the
/// client abandons is a handler the listener drops mid-order: an
/// operator who waited this long has a renewal that ran, and one whose
/// client gave up at a read's timeout has one that did not.
const WRITE_TIMEOUT: Duration = Duration::from_secs(120);

/// How long the connection itself may take to come up.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);

/// Why an HTTPS read source could not be built.
///
/// Only the TLS trust material can fail here: everything else was
/// already checked by [`ServerConfig`], which refuses a non-origin, a
/// plaintext endpoint and a token that cannot travel in a header.
#[derive(Debug, thiserror::Error)]
pub enum HttpsError {
    /// The file named by [`crate::config::CA_BUNDLE_ENV`] could not be
    /// read.
    #[error(
        "cannot read the certificate authority bundle named by {} ({}): {source}",
        crate::config::CA_BUNDLE_ENV,
        path.display()
    )]
    BundleUnreadable {
        /// The path that was named.
        path: std::path::PathBuf,
        /// The operating system's reason, which names no file content.
        source: std::io::Error,
    },
    /// The file was read and holds no certificate this client can use.
    ///
    /// Carries no parse detail on purpose: it would quote what the
    /// parser choked on, a line of whatever file the operator named.
    #[error(
        "the certificate authority bundle named by {} ({}) holds no PEM certificate. \
         It is a file of one or more `-----BEGIN CERTIFICATE-----` blocks: the \
         listener's own certificate when it is self-signed, or the CA that signed it.",
        crate::config::CA_BUNDLE_ENV,
        path.display()
    )]
    BundleNotCertificates {
        /// The path that was named.
        path: std::path::PathBuf,
    },
    /// The HTTP client itself could not be built.
    #[error("cannot build the HTTPS client: {0}")]
    ClientUnbuildable(String),
}

/// An [`AutomationPlane`] reached over HTTPS: the automation listener,
/// from a separate process.
///
/// One client, reused for every call, so the TLS handshake and the
/// connection are paid once rather than per tool call.
pub struct HttpsPlane {
    client: reqwest::Client,
    endpoint: String,
}

impl HttpsPlane {
    /// Build a client for `config`.
    ///
    /// The bearer token becomes a default header marked sensitive, so
    /// it is built once and `reqwest`'s own diagnostics redact it.
    ///
    /// # Errors
    ///
    /// [`HttpsError::BundleUnreadable`] or
    /// [`HttpsError::BundleNotCertificates`] for a CA bundle that is
    /// named and unusable, [`HttpsError::ClientUnbuildable`] when the
    /// TLS backend refuses to start.
    pub fn new(config: &ServerConfig) -> Result<HttpsPlane, HttpsError> {
        let mut authorization = HeaderValue::from_str(&format!("Bearer {}", config.token.reveal()))
            .map_err(|reason| HttpsError::ClientUnbuildable(reason.to_string()))?;
        authorization.set_sensitive(true);

        let mut headers = HeaderMap::new();
        headers.insert(AUTHORIZATION, authorization);
        headers.insert(ACCEPT, HeaderValue::from_static("application/json"));
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static(concat!("lorica-mcp/", env!("CARGO_PKG_VERSION"))),
        );
        // Asserted once as a default header rather than per request:
        // the transport is a property of this process and not of a
        // call, and a default header cannot be forgotten by a new call
        // site the way a per-request one can.
        headers.insert(
            ASSERTED_TRANSPORT_HEADER,
            HeaderValue::from_static(TRANSPORT_MARKER),
        );

        let mut builder = reqwest::Client::builder()
            .default_headers(headers)
            .timeout(REQUEST_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            // No automation read redirects, so following one could
            // only carry the bearer somewhere the configuration never
            // named. `https_only` is the same refusal
            // `ServerConfig` makes of a plaintext endpoint, kept for
            // the request itself so a redirect could not undo it.
            .redirect(reqwest::redirect::Policy::none())
            .https_only(true)
            // The plane is one node and a read tier is not a crawler.
            .pool_max_idle_per_host(2);
        for authority in trusted_extras(config.ca_bundle.as_deref())? {
            builder = builder.add_root_certificate(authority);
        }

        Ok(HttpsPlane {
            client: builder
                .build()
                .map_err(|reason| HttpsError::ClientUnbuildable(reason.to_string()))?,
            endpoint: config.endpoint.clone(),
        })
    }
}

/// The certificates named by `bundle`, or an empty list when none was
/// named.
///
/// Additive: what comes back is added to the platform store and the
/// built-in roots rather than replacing either, so naming an internal
/// CA does not stop a publicly signed listener from verifying.
fn trusted_extras(bundle: Option<&Path>) -> Result<Vec<reqwest::Certificate>, HttpsError> {
    let Some(path) = bundle else {
        return Ok(Vec::new());
    };
    let pem = std::fs::read(path).map_err(|source| HttpsError::BundleUnreadable {
        path: path.to_path_buf(),
        source,
    })?;
    let certificates = reqwest::Certificate::from_pem_bundle(&pem).map_err(|_| {
        // The parse detail is dropped: it quotes what it choked on, and
        // an operator who pointed this at the wrong file would see a
        // line of that file on stderr.
        HttpsError::BundleNotCertificates {
            path: path.to_path_buf(),
        }
    })?;
    if certificates.is_empty() {
        return Err(HttpsError::BundleNotCertificates {
            path: path.to_path_buf(),
        });
    }
    Ok(certificates)
}

impl AutomationPlane for HttpsPlane {
    async fn call(
        &self,
        verb: Verb,
        path: &str,
        body: Option<&serde_json::Value>,
        reason: Reason<'_>,
    ) -> Result<String, PlaneError> {
        let method = match verb {
            Verb::Get => reqwest::Method::GET,
            Verb::Post => reqwest::Method::POST,
            Verb::Put => reqwest::Method::PUT,
            Verb::Delete => reqwest::Method::DELETE,
        };
        let mut request = self
            .client
            .request(method, format!("{}{path}", self.endpoint))
            .timeout(if verb.is_read() {
                REQUEST_TIMEOUT
            } else {
                WRITE_TIMEOUT
            });
        // Serialised here rather than through the client's own JSON
        // helper, which is a feature this crate does not enable: the
        // body is a `Value` the tool layer already bounded, and one
        // `to_vec` is the whole of what that helper would do.
        if let Some(body) = body {
            let bytes = serde_json::to_vec(body)
                .map_err(|reason| PlaneError::Transport(reason.to_string()))?;
            request = request
                .header(CONTENT_TYPE, HeaderValue::from_static("application/json"))
                .body(bytes);
        }
        // Absent where no tool ran, which is the startup introspection.
        // A header naming a tool there would be the false claim this
        // whole arrangement exists to avoid. The grammar check is
        // `tools`' own, the same one the plane's audit layer applies
        // before a claimed name becomes a row: every name this crate
        // can pass comes from the catalogue and already fits, so this
        // is the belt on a value about to enter somebody's audit trail
        // rather than a check anything is expected to fail.
        if let Some(tool) = reason
            .tool()
            .filter(|name| crate::tools::is_legal_tool_name(name))
        {
            request = request.header(ASSERTED_TOOL_HEADER, tool);
        }

        let response = request
            .send()
            .await
            .map_err(|reason| PlaneError::Transport(reason.to_string()))?;
        let status = response.status().as_u16();
        PlaneError::answered(status, bounded_body(response).await?)
    }
}

/// The response body, up to [`MAX_ANSWER_BYTES`].
///
/// Read in chunks rather than with `bytes()`, because the ceiling has
/// to stop the transfer and not merely regret it afterwards.
async fn bounded_body(mut response: reqwest::Response) -> Result<Vec<u8>, PlaneError> {
    let mut body: Vec<u8> = Vec::new();
    loop {
        let chunk = response
            .chunk()
            .await
            .map_err(|reason| PlaneError::Transport(reason.to_string()))?;
        let Some(chunk) = chunk else { break };
        if body.len() + chunk.len() > MAX_ANSWER_BYTES {
            return Err(PlaneError::Transport(format!(
                "the answer is over {MAX_ANSWER_BYTES} bytes, which no automation call produces; \
                 check that the endpoint is a Lorica automation listener and not something in \
                 front of one"
            )));
        }
        body.extend_from_slice(&chunk);
    }
    Ok(body)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::CA_BUNDLE_ENV;

    fn config_with(ca_bundle: Option<std::path::PathBuf>) -> ServerConfig {
        let mut env: Vec<(&str, String)> = vec![
            (
                crate::config::ENDPOINT_ENV,
                "https://lorica.internal.example.org:8443".to_string(),
            ),
            (
                crate::config::TOKEN_ENV,
                "lam_0123456789abcdef.s3cr3t".to_string(),
            ),
        ];
        if let Some(path) = &ca_bundle {
            env.push((CA_BUNDLE_ENV, path.display().to_string()));
        }
        ServerConfig::assemble(
            &[],
            |name| {
                env.iter()
                    .find(|(key, _)| *key == name)
                    .map(|(_, value)| value.clone())
            },
            None,
        )
        .expect("test setup: a complete configuration")
    }

    /// One self-signed certificate in PEM, as an operator's bundle
    /// would carry it.
    fn a_certificate_pem() -> String {
        rcgen::generate_simple_self_signed(vec!["lorica.internal.example.org".to_string()])
            .expect("test setup: a certificate")
            .cert
            .pem()
    }

    #[test]
    fn a_client_builds_with_no_bundle_and_with_one() {
        HttpsPlane::new(&config_with(None)).expect("the platform store alone is enough");

        let dir = tempfile::tempdir().expect("test setup: temp dir");
        let bundle = dir.path().join("internal-ca.pem");
        // Two blocks, because an operator's bundle is a chain as often
        // as it is one certificate.
        std::fs::write(
            &bundle,
            format!("{}{}", a_certificate_pem(), a_certificate_pem()),
        )
        .expect("test setup: the bundle is written");
        HttpsPlane::new(&config_with(Some(bundle))).expect("a named bundle is trusted");
    }

    #[test]
    fn a_bundle_that_is_not_certificates_stops_the_start_and_names_the_path() {
        // The failure this refuses to paper over: an operator points
        // the variable at the wrong file and the client silently trusts
        // the platform store alone, so the first read fails on the
        // certificate they thought they had added.
        let dir = tempfile::tempdir().expect("test setup: temp dir");

        let missing = dir.path().join("absent.pem");
        let refused = HttpsPlane::new(&config_with(Some(missing.clone())))
            .err()
            .expect("an unreadable bundle is refused");
        assert!(
            matches!(refused, HttpsError::BundleUnreadable { .. }),
            "{refused:?}"
        );
        assert!(refused.to_string().contains("absent.pem"), "{refused}");

        let garbage = dir.path().join("notes.txt");
        std::fs::write(&garbage, "this is not a certificate\n").expect("test setup: written");
        let refused = HttpsPlane::new(&config_with(Some(garbage)))
            .err()
            .expect("a file with no certificate in it is refused");
        assert!(
            matches!(refused, HttpsError::BundleNotCertificates { .. }),
            "{refused:?}"
        );
        // And the refusal quotes nothing from inside the file: an
        // operator who named the wrong path must not see a line of it.
        assert!(
            !refused.to_string().contains("this is not a certificate"),
            "{refused}"
        );
    }

    #[test]
    fn this_module_offers_no_way_to_skip_verification() {
        // The property, asserted against this file's own source rather
        // than promised in a comment. `danger_accept_invalid_certs` and
        // its siblings are the switch an operator reaches for when a
        // self-signed certificate is in the way, and the answer here is
        // the CA bundle instead.
        let source = include_str!("http.rs");
        let body = source.split("#[cfg(test)]").next().unwrap_or(source);
        for dangerous in [
            "danger_accept_invalid_certs",
            "danger_accept_invalid_hostnames",
            "tls_built_in_root_certs(false)",
            "use_preconfigured_tls",
        ] {
            assert!(
                !body.contains(dangerous),
                "{dangerous} is reachable from this module"
            );
        }
        // And the scan is worth something: the bundle call it is meant
        // to be the complement of really is here.
        assert!(body.contains("add_root_certificate"));
    }

    #[test]
    fn this_client_follows_no_redirect() {
        // A 3xx from anything terminating TLS with a trusted
        // certificate could otherwise point the client, bearer and all,
        // somewhere the configuration never named. `reqwest` follows ten
        // redirects by default. Asserted against the source because
        // observing it needs a TLS server this crate has no dependency
        // to build; the plaintext half is observed below.
        let source = include_str!("http.rs");
        let body = source.split("#[cfg(test)]").next().unwrap_or(source);
        assert!(body.contains("redirect(reqwest::redirect::Policy::none())"));
    }

    #[tokio::test]
    async fn a_plaintext_url_is_refused_before_anything_connects() {
        // `ServerConfig` refuses an `http://` endpoint; `https_only` is
        // the same refusal kept for the request itself, so a redirect
        // or a future call site cannot undo it. Observed rather than
        // read: a listener on loopback that would receive the bearer
        // receives no connection at all.
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("test setup: bind");
        listener
            .set_nonblocking(true)
            .expect("test setup: nonblocking");
        let port = listener.local_addr().expect("test setup: addr").port();
        let mut plane = HttpsPlane::new(&config_with(None)).expect("a client builds");
        plane.endpoint = format!("http://127.0.0.1:{port}");

        let refused = plane
            .call(
                Verb::Get,
                "/automation/v1/whoami",
                None,
                Reason::Introspection,
            )
            .await
            .expect_err("a plaintext URL is refused");
        assert!(matches!(refused, PlaneError::Transport(_)), "{refused:?}");
        assert!(
            matches!(listener.accept(), Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock),
            "the plaintext listener was connected to"
        );
    }

    #[test]
    fn the_transport_marker_says_which_binding_and_reads_as_mcp() {
        // An operator filtering the audit trail for anything a model
        // drove matches the prefix; one asking which door it came
        // through reads the whole word.
        assert!(TRANSPORT_MARKER.starts_with("mcp"));
        assert_eq!(TRANSPORT_MARKER, "mcp-stdio");
        // Both headers are lowercase and carry the word that says what
        // they are worth to a reader of the row.
        for header in [ASSERTED_TOOL_HEADER, ASSERTED_TRANSPORT_HEADER] {
            assert_eq!(header, header.to_lowercase(), "{header}");
            assert!(header.contains("asserted"), "{header}");
        }
    }
}
