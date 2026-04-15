// Copyright 2026 Rwx-G (Lorica)
//
// Licensed under the Apache License, Version 2.0 (the "License");

//! Listener-side mTLS wiring. Collects the union of client-CA PEM
//! bundles across all routes that have mTLS enabled, builds a single
//! `WebPkiClientVerifier`, and exposes it for installation on the
//! HTTPS listener's `TlsSettings`.
//!
//! The verifier is built with `allow_unauthenticated()` so connections
//! without a client cert still complete the TLS handshake. Per-route
//! enforcement lives in the proxy layer (`proxy_wiring::evaluate_mtls`),
//! which lets different routes on the same listener have different
//! policies (require vs. opportunistic vs. off).
//!
//! Limitation: rustls `ServerConfig` is immutable after build, so
//! changes to the CA bundle require a restart. Toggling `required`
//! and editing `allowed_organizations` are still hot-reloadable since
//! those checks happen in the proxy layer, not at the handshake.

use std::sync::Arc;

use lorica_config::models::Route;
use lorica_tls::{ClientCertVerifier, RootCertStore, WebPkiClientVerifier};

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
        // rustls_pemfile returns items one-by-one; keep only X.509
        // CERTIFICATE blocks. A single PEM bundle can carry an
        // intermediate + root, and we want both in the store.
        let mut reader = std::io::Cursor::new(pem_text.as_bytes());
        let items: Vec<_> = rustls_pemfile::certs(&mut reader)
            .filter_map(|r| r.ok())
            .collect();
        for der in items {
            match store.add(der) {
                Ok(()) => added += 1,
                Err(e) => tracing::warn!(
                    error = %e,
                    "mtls: skipping CA cert that rustls rejected"
                ),
            }
        }
    }

    if added == 0 {
        tracing::warn!(
            "mtls: no usable CA certs found across configured routes; mTLS is effectively disabled"
        );
        return None;
    }
    Some(store)
}

/// Build an mTLS client cert verifier from the given root store.
/// Uses `allow_unauthenticated()` so the TLS handshake accepts clients
/// that omit a cert; enforcement is delegated to the proxy layer
/// (per-route `required` / `allowed_organizations`).
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
/// edits to `mtls.ca_cert_pem` - those require a restart because
/// rustls `ServerConfig` is immutable, and we want to surface that
/// via a warn log instead of silently accepting stale CAs.
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
}
