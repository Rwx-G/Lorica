//! The checks of a stream's TLS fields that `Stream::validate` cannot
//! make, because they need X.509 parsing or the certificate rows (Story
//! 12.4 D-h, D-k). Every stream writer of this API runs them: create,
//! update, and the TOML import with its preview, so none of them accepts
//! what another refuses.
//!
//! Two steps, so the one that reads no row runs before the store lock:
//! [`check_bundles`] parses the PEM bundles with the route's validator
//! and puts them in the form it stores; [`check_certificates`] checks the
//! certificates the stream names against the rows they name. Both refuse
//! `422` naming the stream and the field, and answer the warnings a
//! write carries back to the operator: a client CA bundle that trusts
//! more than the CAs it lists (the 1.10.3 check), and a wildcard rule
//! name that routes deeper names than any certificate serves.

use std::net::IpAddr;

use lorica_config::models::{
    canonical_server_name, Certificate, Stream, StreamMatcher, StreamTlsMode,
};
use lorica_tls::cert_resolver::{ip_sans_of_leaf, lookup_keys};

use crate::error::ApiError;
use crate::routes::mtls::{
    build_mtls_config, log_mtls_bundle_trust_warnings, mtls_bundle_trust_warnings,
    MtlsConfigRequest,
};

/// The field a terminating stream's client CA bundle lives under.
const CLIENT_AUTH_FIELD: &str = "tls_terminate.client_auth";

/// The `422` of `stream` for a bundle the route's validator refused,
/// its message speaking of the stream's field rather than of a route's
/// `mtls` object.
fn bundle_refusal(stream: &str, field: &str, refusal: ApiError) -> ApiError {
    match refusal {
        ApiError::BadRequest(message) => ApiError::Unprocessable(format!(
            "stream `{stream}`: {}",
            message.replace("mtls.", &format!("{field}."))
        )),
        other => other,
    }
}

/// Parse every PEM bundle of `stream` with the route's validator
/// (`build_mtls_config`: not blank, at most 1 MiB, every `CERTIFICATE`
/// block a valid X.509 certificate, at least one; the organization list
/// trimmed and deduplicated) and store each in the form it answers: the
/// client CA bundle of `tls_terminate.client_auth`, and the server CA
/// bundle of `upstream_tls.ca_cert_pem`.
///
/// A client CA bundle that trusts more than the CAs it lists (a root
/// beside other certificates, a CA beside one it issued) is accepted,
/// as on a route: it is logged as a route write logs it, and each
/// finding is answered as a warning naming the stream. A server CA
/// bundle draws no such warning: trusting a root is what a bundle of
/// server CAs is for.
///
/// # Errors
///
/// `422` naming the stream and the field when a bundle does not parse.
pub(crate) fn check_bundles(stream: &mut Stream) -> Result<Vec<String>, ApiError> {
    let name = stream.name.clone();
    let mut warnings: Vec<String> = Vec::new();
    if let Some(client_auth) = stream
        .tls_terminate
        .as_mut()
        .and_then(|terminate| terminate.client_auth.as_mut())
    {
        let checked = build_mtls_config(&MtlsConfigRequest {
            ca_cert_pem: client_auth.ca_cert_pem.clone(),
            required: client_auth.required,
            allowed_organizations: client_auth.allowed_organizations.clone(),
        })
        .map_err(|refusal| bundle_refusal(&name, CLIENT_AUTH_FIELD, refusal))?;
        log_mtls_bundle_trust_warnings(&checked);
        for warning in mtls_bundle_trust_warnings(&checked.ca_cert_pem) {
            warnings.push(format!(
                "stream `{name}`: {CLIENT_AUTH_FIELD}.ca_cert_pem: {}",
                warning.replace("this route", "this stream")
            ));
        }
        *client_auth = checked;
    }
    if let Some(pem) = stream
        .upstream_tls
        .as_mut()
        .and_then(|upstream| upstream.ca_cert_pem.as_mut())
    {
        let checked = build_mtls_config(&MtlsConfigRequest {
            ca_cert_pem: pem.clone(),
            required: false,
            allowed_organizations: Vec::new(),
        })
        .map_err(|refusal| bundle_refusal(&name, "upstream_tls", refusal))?;
        *pem = checked.ca_cert_pem;
    }
    Ok(warnings)
}

/// The names `certificate` is looked up by in the node's resolver: its
/// domain and every SAN, lowercased, as `CertResolver::reload` indexes
/// them.
fn served_names(certificate: &Certificate) -> impl Iterator<Item = String> + '_ {
    std::iter::once(&certificate.domain)
        .chain(&certificate.san_domains)
        .map(|name| name.to_lowercase())
}

/// The `iPAddress` SANs of the leaf of `certificate`, read as the
/// resolver's local-address index reads them; none when the stored PEM
/// does not parse.
fn ip_sans(certificate: &Certificate) -> Vec<IpAddr> {
    let Some(leaf) = pem::parse_many(certificate.cert_pem.as_bytes())
        .ok()
        .and_then(|blocks| blocks.into_iter().find(|b| b.tag() == "CERTIFICATE"))
    else {
        return Vec::new();
    };
    match x509_parser::parse_x509_certificate(leaf.contents()) {
        Ok((_, parsed)) => ip_sans_of_leaf(&parsed),
        Err(_) => Vec::new(),
    }
}

/// Check the certificates `stream` names against `certificates`, the
/// rows the write will stand beside (the stored ones, or an import
/// file's):
///
/// - every `tls_terminate.certificate_ids` entry and the
///   `upstream_tls.client_certificate_id` name a row;
/// - on a terminating stream, every exact server name of its `tls`
///   rules is served by one of its certificates, by the lookup the
///   handshake runs (`lorica_tls::cert_resolver::lookup_keys`: the name,
///   then the one-label wildcard above it), and every wildcard rule name
///   by a certificate carrying that wildcard itself;
/// - on a terminating stream with a `no_sni` rule, one of its
///   certificates carries an `iPAddress` SAN, and the listen address
///   among them when the stream listens on a specific one: a client
///   naming no server is served the certificate of the address it
///   dialed.
///
/// A wildcard rule name of a terminating stream draws a warning: the
/// rule routes names at every depth (Story 12.4 D-c), while a
/// certificate serves one label, so a deeper name fails its handshake
/// (`no_certificate`).
///
/// Checked at write only: a renewal that drops a SAN shows in the
/// `no_certificate` counter, it is not refused.
///
/// # Errors
///
/// `422` naming the stream, the field or rule, and the certificates
/// listed.
pub(crate) fn check_certificates(
    stream: &Stream,
    certificates: &[Certificate],
) -> Result<Vec<String>, ApiError> {
    let name = stream.name.as_str();
    let row = |id: &str| certificates.iter().find(|c| c.id == id);
    let terminate_ids: &[String] = stream
        .tls_terminate
        .as_ref()
        .map_or(&[], |terminate| terminate.certificate_ids.as_slice());
    for id in terminate_ids {
        if row(id).is_none() {
            return Err(ApiError::Unprocessable(format!(
                "stream `{name}`: tls_terminate.certificate_ids: certificate {id} does not exist"
            )));
        }
    }
    if let Some(id) = stream
        .upstream_tls
        .as_ref()
        .and_then(|upstream| upstream.client_certificate_id.as_deref())
    {
        if row(id).is_none() {
            return Err(ApiError::Unprocessable(format!(
                "stream `{name}`: upstream_tls.client_certificate_id: certificate {id} does not \
                 exist"
            )));
        }
    }
    if stream.tls_mode != StreamTlsMode::Terminate {
        return Ok(Vec::new());
    }
    let listed: Vec<&Certificate> = terminate_ids.iter().filter_map(|id| row(id)).collect();
    let listing = listed
        .iter()
        .map(|c| format!("{} ({})", c.id, c.domain))
        .collect::<Vec<String>>()
        .join(", ");
    let mut warnings: Vec<String> = Vec::new();
    for rule in &stream.match_rules {
        for server_name in rule.matcher.server_names() {
            let server_name = canonical_server_name(server_name);
            let covered = match server_name.strip_prefix("*.") {
                Some(suffix) => {
                    warnings.push(format!(
                        "stream `{name}`: rule `{}` routes `{server_name}` at every depth, while \
                         a certificate serves one label under it: a client naming a deeper name \
                         such as `a.b.{suffix}` fails its handshake (no_certificate)",
                        rule.name
                    ));
                    listed
                        .iter()
                        .any(|c| served_names(c).any(|served| served == server_name))
                }
                None => {
                    let (exact, wildcard) = lookup_keys(&server_name);
                    listed.iter().any(|c| {
                        served_names(c)
                            .any(|served| served == exact || Some(&served) == wildcard.as_ref())
                    })
                }
            };
            if !covered {
                let need = if server_name.starts_with("*.") {
                    "a wildcard rule name needs a certificate carrying that wildcard itself"
                } else {
                    "a certificate serves it when its domain or a SAN is the name or the \
                     wildcard one label above it"
                };
                return Err(ApiError::Unprocessable(format!(
                    "stream `{name}`: rule `{}`: no certificate of tls_terminate.certificate_ids \
                     ({listing}) serves `{server_name}`; {need}",
                    rule.name
                )));
            }
        }
    }
    if let Some(rule) = stream
        .match_rules
        .iter()
        .find(|rule| matches!(rule.matcher, StreamMatcher::NoSni { .. }))
    {
        let addresses: Vec<IpAddr> = listed.iter().flat_map(|c| ip_sans(c)).collect();
        let listen = stream.listen_address;
        let missing = if addresses.is_empty() {
            Some("an IP address SAN".to_string())
        } else if !listen.is_unspecified() && !addresses.contains(&listen) {
            Some(format!("the listen address {listen} as an IP address SAN"))
        } else {
            None
        };
        if let Some(missing) = missing {
            return Err(ApiError::Unprocessable(format!(
                "stream `{name}`: rule `{}` admits clients naming no server, which are served \
                 the certificate whose IP address SAN is the address they dialed; no certificate \
                 of tls_terminate.certificate_ids ({listing}) carries {missing}",
                rule.name
            )));
        }
    }
    Ok(warnings)
}
