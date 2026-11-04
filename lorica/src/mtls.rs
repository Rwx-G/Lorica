// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");

//! mTLS client-certificate verification, in two layers.
//!
//! **The listener.** One HTTPS listener serves every route, and a rustls
//! `ServerConfig` takes one client verifier. [`build_from_routes`]
//! builds it from the union of the CA bundles of every route with mTLS,
//! with `allow_unauthenticated()` so a client without a certificate still
//! completes the handshake. Its job is to make the handshake ask for a
//! certificate, prove the client holds the key, and refuse a chain that
//! no route trusts. It cannot tell which route the client is after, so
//! a certificate it accepts may come from any route's CA.
//!
//! **The route.** [`RouteClientVerifier`] holds one route's own bundle,
//! built with the route snapshot (`ProxyConfig::from_store`, at startup
//! and on every reload). The proxy layer verifies the presented chain
//! against it before it reads any identity from the certificate
//! (`proxy_wiring::route_client_cert`), so a certificate from route A's
//! CA is no certificate at all on route B, whatever its `O=` says. The
//! policy itself (`required`, `allowed_organizations`) is
//! `proxy_wiring::evaluate_mtls`.
//!
//! **Reloads.** rustls `ServerConfig` is immutable after build, so the
//! listener keeps the union it started with until a restart. The route
//! layer follows every reload. Together:
//! - removing a CA from a route, or pointing a route at a CA another
//!   route already trusts, takes effect on reload;
//! - a CA no route trusted at startup is unknown to the listener, so
//!   its certificates fail the handshake until a restart;
//! - a CA removed from every route still passes the handshake until a
//!   restart, and is refused by every route from the reload on.
//!
//! `required` and `allowed_organizations` are read per request and
//! always hot-reload.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

use lorica_config::models::Route;
use lorica_tls::{ClientCertVerifier, RootCertStore, UnixTime, WebPkiClientVerifier};
use rustls_pki_types::{pem::PemObject, CertificateDer};

/// Aggregate all mTLS CA PEMs found across `routes` into a single
/// rustls `RootCertStore`. Returns `None` when no route has mTLS
/// enabled (caller uses `with_no_client_auth()` in that case).
///
/// Invalid or empty CA blocks are logged and skipped rather than
/// failing the listener - the API validator already rejects malformed
/// PEM at write time, so anything surviving to here is either a
/// post-write corruption or a rare race. Routes with a valid CA keep
/// working; the offending route's cert chain won't verify, and its
/// `required = true` enforcement will deny requests - which is the
/// fail-safe behavior.
pub fn build_union_root_store(routes: &[Route]) -> Option<RootCertStore> {
    let pems: Vec<&str> = routes
        .iter()
        .filter_map(|r| r.mtls.as_ref())
        .map(|m| m.ca_cert_pem.as_str())
        .filter(|p| !p.trim().is_empty())
        .collect();
    if pems.is_empty() {
        return None;
    }

    let mut store = RootCertStore::empty();
    let mut added = 0usize;
    for pem_text in pems {
        added += add_pem_bundle(&mut store, pem_text);
    }

    if added == 0 {
        tracing::warn!(
            "mtls: no usable CA certs found across configured routes; mTLS is effectively disabled"
        );
        return None;
    }
    Some(store)
}

/// Add every certificate of one PEM bundle to `store` as a trust anchor
/// and return how many were added.
///
/// `CertificateDer::pem_slice_iter` walks every `CERTIFICATE` block and
/// skips other block types (PRIVATE KEY, etc.). Every certificate becomes
/// an anchor on its own, the X.509 semantics nginx shares. A bundle that
/// carries a root therefore trusts every CA the root signed, the
/// siblings of the issuing CA pasted beside it included, as long as the
/// client sends its own issuing CA as an intermediate. The bundle a route
/// means to restrict to some issuing CAs holds those and not their root;
/// the API's PEM validation warns about the other shape, and still
/// accepts it.
fn add_pem_bundle(store: &mut RootCertStore, pem_text: &str) -> usize {
    let mut added = 0usize;
    for der_result in CertificateDer::pem_slice_iter(pem_text.as_bytes()) {
        let der = match der_result {
            Ok(d) => d,
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "mtls: skipping CA cert block that failed PEM parse"
                );
                continue;
            }
        };
        match store.add(der) {
            Ok(()) => added += 1,
            Err(e) => tracing::warn!(
                error = %e,
                "mtls: skipping CA cert that rustls rejected"
            ),
        }
    }
    added
}

/// Source of [`RouteClientVerifier::memo_key`]. Every verifier built gets
/// a fresh value, so a verdict a connection cached for one route or one
/// snapshot is never read back for another.
static NEXT_MEMO_KEY: AtomicU64 = AtomicU64::new(1);

/// One route's client-CA bundle, ready to verify a presented chain.
///
/// Built with the route snapshot, never per request. A chain verifies
/// when it leads from its end-entity, through the intermediates the
/// client sent, to a certificate of this bundle, with every certificate
/// inside its validity period and the end-entity usable for client
/// authentication: what `WebPkiClientVerifier` checks at a handshake.
/// Proof that the client holds the end-entity's key is the handshake's
/// job and is not repeated here.
#[derive(Debug)]
pub struct RouteClientVerifier {
    verifier: Arc<dyn ClientCertVerifier>,
    memo_key: u64,
}

impl RouteClientVerifier {
    /// Build the verifier for one route's `ca_cert_pem`.
    ///
    /// Returns `None` when the bundle holds no usable certificate. The
    /// route then verifies no chain at all: a `required` route refuses
    /// every client, which is the fail-safe reading of a broken bundle.
    pub fn from_pem(route_id: &str, ca_pem: &str) -> Option<Self> {
        let mut roots = RootCertStore::empty();
        if add_pem_bundle(&mut roots, ca_pem) == 0 {
            tracing::warn!(
                route_id = %route_id,
                "mtls: route CA bundle holds no usable certificate; no client certificate will verify on this route"
            );
            return None;
        }
        // An explicit provider, unlike the listener's `builder`: this runs
        // on every snapshot build, tests and reloads included, and must
        // not depend on a process-wide default having been installed.
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        match WebPkiClientVerifier::builder_with_provider(Arc::new(roots), provider).build() {
            Ok(verifier) => Some(RouteClientVerifier {
                verifier,
                memo_key: NEXT_MEMO_KEY.fetch_add(1, Ordering::Relaxed),
            }),
            Err(e) => {
                tracing::warn!(
                    route_id = %route_id,
                    error = ?e,
                    "mtls: failed to build the route's client verifier; no client certificate will verify on this route"
                );
                None
            }
        }
    }

    /// Whether `chain` (DER, end-entity first, then the intermediates in
    /// the order the client sent them) verifies against this route's
    /// bundle now. An empty chain never does.
    pub fn verifies(&self, chain: &[Vec<u8>]) -> bool {
        let Some((end_entity, intermediates)) = chain.split_first() else {
            return false;
        };
        let end_entity = CertificateDer::from(end_entity.as_slice());
        let intermediates: Vec<CertificateDer<'_>> = intermediates
            .iter()
            .map(|der| CertificateDer::from(der.as_slice()))
            .collect();
        self.verifier
            .verify_client_cert(&end_entity, &intermediates, UnixTime::now())
            .is_ok()
    }

    /// The key a connection files this verifier's verdict under
    /// (`SslDigest::peer_chain_verdicts`). Unique to this verifier, hence
    /// to one route in one snapshot: a reload builds new verifiers, so a
    /// changed bundle is verified afresh on connections already open.
    pub fn memo_key(&self) -> u64 {
        self.memo_key
    }
}

/// Build an mTLS client cert verifier from the given root store.
/// Uses `allow_unauthenticated()` so the TLS handshake accepts clients
/// that omit a cert; enforcement is delegated to the proxy layer
/// (per-route chain verification, `required` and
/// `allowed_organizations`).
///
/// Returns `None` when verifier construction fails (unusable roots);
/// the listener then falls back to no-client-auth and per-route
/// enforcement with `required = true` will correctly deny every
/// request on affected routes.
pub fn build_verifier(roots: RootCertStore) -> Option<Arc<dyn ClientCertVerifier>> {
    match WebPkiClientVerifier::builder(Arc::new(roots))
        .allow_unauthenticated()
        .build()
    {
        Ok(v) => Some(v as Arc<dyn ClientCertVerifier>),
        Err(e) => {
            tracing::warn!(
                error = ?e,
                "mtls: failed to build WebPkiClientVerifier; falling back to no-client-auth"
            );
            None
        }
    }
}

/// Convenience: collect routes → build verifier in one call. Returns
/// `None` when no route has mTLS or when verifier construction fails.
pub fn build_from_routes(routes: &[Route]) -> Option<Arc<dyn ClientCertVerifier>> {
    let roots = build_union_root_store(routes)?;
    build_verifier(roots)
}

/// Deterministic fingerprint of the union CA bundle installed on the
/// listener. Used by `reload_proxy_config` to detect post-startup
/// edits to `mtls.ca_cert_pem`: the per-route check follows them on
/// reload, but the listener keeps the union it started with until a
/// restart (rustls `ServerConfig` is immutable), and we want to surface
/// that via a warn log rather than leave it silent.
///
/// Returns `None` when no route has mTLS configured (fingerprint
/// undefined; also how we distinguish "listener has no verifier" from
/// "listener has a verifier with no CAs"). Two route sets with
/// identical PEM bytes in identical order yield identical fingerprints.
/// The fingerprint is stable across restarts with the same DB state.
pub fn compute_ca_fingerprint(routes: &[Route]) -> Option<String> {
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};
    let mut pems: Vec<String> = routes
        .iter()
        .filter_map(|r| r.mtls.as_ref())
        .map(|m| m.ca_cert_pem.trim().to_string())
        .filter(|p| !p.is_empty())
        .collect();
    if pems.is_empty() {
        return None;
    }
    // Sort so the fingerprint is insensitive to route order (two
    // deployments with the same CAs but different route creation
    // order produce the same fingerprint - easier to reason about in
    // logs).
    pems.sort();
    let mut h = DefaultHasher::new();
    for pem in &pems {
        pem.hash(&mut h);
    }
    Some(format!("{:016x}", h.finish()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use lorica_config::models::{LoadBalancing, MtlsConfig, Route, WafMode};

    fn init_crypto_once() {
        use std::sync::Once;
        static ONCE: Once = Once::new();
        ONCE.call_once(|| {
            let _ = rustls::crypto::ring::default_provider().install_default();
        });
    }

    fn make_route(id: &str, mtls: Option<MtlsConfig>) -> Route {
        let now = Utc::now();
        Route {
            id: id.into(),
            hostname: format!("{id}.example.com"),
            path_prefix: "/".into(),
            certificate_id: None,
            load_balancing: LoadBalancing::RoundRobin,
            waf_enabled: false,
            waf_mode: WafMode::Detection,
            enabled: true,
            force_https: false,
            redirect_hostname: None,
            redirect_to: None,
            hostname_aliases: Vec::new(),
            proxy_headers: std::collections::HashMap::new(),
            response_headers: std::collections::HashMap::new(),
            security_headers: "moderate".into(),
            connect_timeout_s: 5,
            read_timeout_s: 60,
            send_timeout_s: 60,
            strip_path_prefix: None,
            add_path_prefix: None,
            path_rewrite_pattern: None,
            path_rewrite_replacement: None,
            access_log_enabled: true,
            proxy_headers_remove: Vec::new(),
            response_headers_remove: Vec::new(),
            max_request_body_bytes: None,
            websocket_enabled: true,
            rate_limit_rps: None,
            rate_limit_burst: None,
            ip_allowlist: Vec::new(),
            ip_denylist: Vec::new(),
            cors_allowed_origins: Vec::new(),
            cors_allowed_methods: Vec::new(),
            cors_max_age_s: None,
            compression_enabled: false,
            retry_attempts: None,
            cache_enabled: false,
            cache_ttl_s: 300,
            cache_max_bytes: 52428800,
            max_connections: None,
            slowloris_threshold_ms: 5000,
            auto_ban_threshold: None,
            auto_ban_duration_s: 3600,
            path_rules: Vec::new(),
            return_status: None,
            sticky_session: false,
            basic_auth_username: None,
            basic_auth_password_hash: None,
            stale_while_revalidate_s: 10,
            stale_if_error_s: 60,
            retry_on_methods: Vec::new(),
            maintenance_mode: false,
            error_page_html: None,
            cache_vary_headers: Vec::new(),
            header_rules: Vec::new(),
            traffic_splits: Vec::new(),
            forward_auth: None,
            mirror: None,
            response_rewrite: None,
            mtls,
            rate_limit: None,
            geoip: None,
            bot_protection: None,
            group_name: String::new(),
            node_selector: Vec::new(),
            ai_bot_policy: None,
            ai_bot_spoofed_fallback: None,
            serve_robots_txt: false,
            managed_by: None,
            waf_body_scan_max_bytes: None,
            created_at: now,
            updated_at: now,
        }
    }

    fn gen_ca_pem() -> String {
        let mut params = rcgen::CertificateParams::new(vec!["Test CA".into()]).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        let key = rcgen::KeyPair::generate().unwrap();
        params.self_signed(&key).unwrap().pem()
    }

    #[test]
    fn union_store_empty_when_no_mtls() {
        init_crypto_once();
        let routes = vec![make_route("a", None), make_route("b", None)];
        assert!(build_union_root_store(&routes).is_none());
    }

    #[test]
    fn union_store_accepts_single_pem() {
        init_crypto_once();
        let mtls = MtlsConfig {
            ca_cert_pem: gen_ca_pem(),
            required: true,
            allowed_organizations: Vec::new(),
        };
        let routes = vec![make_route("a", Some(mtls))];
        let store = build_union_root_store(&routes).expect("store");
        assert!(!store.is_empty());
    }

    #[test]
    fn union_store_merges_two_pems() {
        init_crypto_once();
        let pem_a = gen_ca_pem();
        let pem_b = gen_ca_pem();
        assert_ne!(pem_a, pem_b, "rcgen generated identical PEMs");
        let routes = vec![
            make_route(
                "a",
                Some(MtlsConfig {
                    ca_cert_pem: pem_a,
                    required: false,
                    allowed_organizations: Vec::new(),
                }),
            ),
            make_route(
                "b",
                Some(MtlsConfig {
                    ca_cert_pem: pem_b,
                    required: true,
                    allowed_organizations: Vec::new(),
                }),
            ),
        ];
        let store = build_union_root_store(&routes).expect("store");
        assert!(store.len() >= 2, "expected both CAs, got {}", store.len());
    }

    #[test]
    fn union_store_tolerates_garbage_pem() {
        init_crypto_once();
        let routes = vec![make_route(
            "a",
            Some(MtlsConfig {
                ca_cert_pem: "not-a-pem".into(),
                required: true,
                allowed_organizations: Vec::new(),
            }),
        )];
        // Garbage yields no cert; function returns None with a warn log.
        assert!(build_union_root_store(&routes).is_none());
    }

    #[test]
    fn build_verifier_round_trip() {
        init_crypto_once();
        let mtls = MtlsConfig {
            ca_cert_pem: gen_ca_pem(),
            required: false,
            allowed_organizations: Vec::new(),
        };
        let routes = vec![make_route("a", Some(mtls))];
        assert!(build_from_routes(&routes).is_some());
    }

    #[test]
    fn fingerprint_none_when_no_mtls_routes() {
        let routes = vec![make_route("a", None)];
        assert!(compute_ca_fingerprint(&routes).is_none());
    }

    #[test]
    fn fingerprint_stable_across_route_order() {
        // Same CAs in different route order must produce the same
        // fingerprint - guards against spurious drift warnings when
        // an operator reorders routes.
        let pem_a = gen_ca_pem();
        let pem_b = gen_ca_pem();
        let r1 = make_route(
            "a",
            Some(MtlsConfig {
                ca_cert_pem: pem_a.clone(),
                required: false,
                allowed_organizations: Vec::new(),
            }),
        );
        let r2 = make_route(
            "b",
            Some(MtlsConfig {
                ca_cert_pem: pem_b.clone(),
                required: false,
                allowed_organizations: Vec::new(),
            }),
        );
        let fp1 = compute_ca_fingerprint(&[r1.clone(), r2.clone()]);
        let fp2 = compute_ca_fingerprint(&[r2, r1]);
        assert_eq!(fp1, fp2);
        assert!(fp1.is_some());
    }

    #[test]
    fn fingerprint_changes_when_pem_changes() {
        let pem_a = gen_ca_pem();
        let pem_b = gen_ca_pem();
        assert_ne!(pem_a, pem_b);
        let r_a = make_route(
            "a",
            Some(MtlsConfig {
                ca_cert_pem: pem_a,
                required: false,
                allowed_organizations: Vec::new(),
            }),
        );
        let r_b = make_route(
            "a",
            Some(MtlsConfig {
                ca_cert_pem: pem_b,
                required: false,
                allowed_organizations: Vec::new(),
            }),
        );
        let fp_a = compute_ca_fingerprint(&[r_a]);
        let fp_b = compute_ca_fingerprint(&[r_b]);
        assert!(fp_a.is_some() && fp_b.is_some());
        assert_ne!(fp_a, fp_b);
    }

    #[test]
    fn fingerprint_insensitive_to_surrounding_whitespace() {
        // Operators sometimes paste PEM with trailing newlines; the
        // API validator trims, but if the DB got a value set via
        // another path we still want the fingerprint to be stable
        // across whitespace-only differences.
        let pem = gen_ca_pem();
        let fp1 = compute_ca_fingerprint(&[make_route(
            "a",
            Some(MtlsConfig {
                ca_cert_pem: pem.clone(),
                required: false,
                allowed_organizations: Vec::new(),
            }),
        )]);
        let fp2 = compute_ca_fingerprint(&[make_route(
            "a",
            Some(MtlsConfig {
                ca_cert_pem: format!("\n\n  {pem}\n\n"),
                required: false,
                allowed_organizations: Vec::new(),
            }),
        )]);
        assert_eq!(fp1, fp2);
    }

    #[test]
    fn fingerprint_ignores_required_and_org_flips() {
        // Toggling required or editing allowed_organizations must NOT
        // change the fingerprint - those are hot-reloadable and we
        // don't want spurious "CA changed" warnings for them.
        let pem = gen_ca_pem();
        let fp_strict = compute_ca_fingerprint(&[make_route(
            "a",
            Some(MtlsConfig {
                ca_cert_pem: pem.clone(),
                required: true,
                allowed_organizations: vec!["Acme".into()],
            }),
        )]);
        let fp_loose = compute_ca_fingerprint(&[make_route(
            "a",
            Some(MtlsConfig {
                ca_cert_pem: pem,
                required: false,
                allowed_organizations: Vec::new(),
            }),
        )]);
        assert_eq!(fp_strict, fp_loose);
    }

    // ---- RouteClientVerifier ----

    /// A CA (root or intermediate) able to sign further certificates.
    struct TestCa {
        pem: String,
        der: Vec<u8>,
        issuer: rcgen::Issuer<'static, rcgen::KeyPair>,
    }

    fn ca_params(cn: &str) -> rcgen::CertificateParams {
        let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        params
    }

    fn root_ca(cn: &str) -> TestCa {
        let params = ca_params(cn);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.self_signed(&key).unwrap();
        TestCa {
            pem: cert.pem(),
            der: cert.der().to_vec(),
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    fn intermediate_ca(parent: &TestCa, cn: &str) -> TestCa {
        let params = ca_params(cn);
        let key = rcgen::KeyPair::generate().unwrap();
        let cert = params.signed_by(&key, &parent.issuer).unwrap();
        TestCa {
            pem: cert.pem(),
            der: cert.der().to_vec(),
            issuer: rcgen::Issuer::new(params, key),
        }
    }

    fn leaf(issuer: &TestCa, org: &str) -> Vec<u8> {
        let mut params = rcgen::CertificateParams::new(Vec::new()).unwrap();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "client");
        params
            .distinguished_name
            .push(rcgen::DnType::OrganizationName, org);
        let key = rcgen::KeyPair::generate().unwrap();
        params
            .signed_by(&key, &issuer.issuer)
            .unwrap()
            .der()
            .to_vec()
    }

    fn verifier_for(ca: &TestCa) -> RouteClientVerifier {
        init_crypto_once();
        RouteClientVerifier::from_pem("r", &ca.pem).expect("verifier")
    }

    #[test]
    fn route_verifier_accepts_a_leaf_of_its_own_ca() {
        let ca_b = root_ca("CA B");
        assert!(verifier_for(&ca_b).verifies(&[leaf(&ca_b, "Beta")]));
    }

    #[test]
    fn route_verifier_refuses_a_leaf_of_another_ca() {
        let ca_a = root_ca("CA A");
        let ca_b = root_ca("CA B");
        assert!(!verifier_for(&ca_b).verifies(&[leaf(&ca_a, "Acme")]));
    }

    #[test]
    fn route_verifier_refuses_another_ca_leaf_carrying_the_expected_org() {
        // The organization is the issuing CA's say-so: a leaf from the
        // wrong CA is refused whatever it claims.
        let ca_a = root_ca("CA A");
        let ca_b = root_ca("CA B");
        assert!(!verifier_for(&ca_b).verifies(&[leaf(&ca_a, "Beta")]));
    }

    #[test]
    fn route_verifier_refuses_a_bare_ca_certificate_and_an_empty_chain() {
        let ca_b = root_ca("CA B");
        let verifier = verifier_for(&ca_b);
        assert!(!verifier.verifies(&[]));
        assert!(!verifier.verifies(&[b"not a certificate".to_vec()]));
    }

    #[test]
    fn route_verifier_follows_intermediates_the_client_sends() {
        let root = root_ca("Root B");
        let intermediate = intermediate_ca(&root, "Issuing B");
        let client = leaf(&intermediate, "Beta");
        let verifier = verifier_for(&root);
        assert!(verifier.verifies(&[client.clone(), intermediate.der.clone()]));
        // Without the intermediate the chain does not reach the root.
        assert!(!verifier.verifies(&[client]));
    }

    #[test]
    fn route_verifier_accepts_a_bundle_that_stops_at_the_intermediate() {
        let root = root_ca("Root B");
        let intermediate = intermediate_ca(&root, "Issuing B");
        assert!(verifier_for(&intermediate).verifies(&[leaf(&intermediate, "Beta")]));
    }

    #[test]
    fn route_verifier_refuses_a_sibling_intermediate_of_the_same_root() {
        // A bundle holding only one issuing CA does not trust its
        // sibling, even though both chain to the same root.
        let root = root_ca("Root");
        let issuing_a = intermediate_ca(&root, "Issuing A");
        let issuing_b = intermediate_ca(&root, "Issuing B");
        let chain = vec![leaf(&issuing_a, "Acme"), issuing_a.der.clone()];
        assert!(!verifier_for(&issuing_b).verifies(&chain));
    }

    #[test]
    fn route_verifier_with_the_root_in_its_bundle_trusts_every_ca_the_root_signed() {
        // The anchor semantics the API warns about, kept executable: a
        // bundle of Issuing B and its root accepts a leaf of Issuing A
        // presented with Issuing A, because the root is an anchor.
        let root = root_ca("Root");
        let issuing_a = intermediate_ca(&root, "Issuing A");
        let issuing_b = intermediate_ca(&root, "Issuing B");
        init_crypto_once();
        let bundle = format!("{}{}", issuing_b.pem, root.pem);
        let verifier = RouteClientVerifier::from_pem("r", &bundle).expect("verifier");
        assert!(verifier.verifies(&[leaf(&issuing_a, "Acme"), issuing_a.der.clone()]));
        // Without the root, the sibling is refused.
        assert!(!verifier_for(&issuing_b).verifies(&[leaf(&issuing_a, "Acme"), issuing_a.der]));
    }

    #[test]
    fn route_verifier_none_for_a_bundle_without_certificates() {
        init_crypto_once();
        assert!(RouteClientVerifier::from_pem("r", "not-a-pem").is_none());
    }

    #[test]
    fn route_verifiers_get_distinct_memo_keys() {
        let ca = root_ca("CA");
        assert_ne!(verifier_for(&ca).memo_key(), verifier_for(&ca).memo_key());
    }
}
