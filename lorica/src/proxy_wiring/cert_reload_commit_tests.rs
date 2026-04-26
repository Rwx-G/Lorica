//! White-box regression tests for the v1.5.2 worker-mode cert
//! hot-reload bug (audit M-22 closure).
//!
//! The original bug : `handle_config_reload_commit` (the worker-side
//! handler for the two-phase RPC commit) did not call
//! `reload_cert_resolver` after publishing the ArcSwap. The call
//! existed on the legacy `CommandType::ConfigReload` path and on the
//! single-process `config_reload_rx` listener, but was never ported
//! to the new pipelined-RPC path. As a result, in worker mode any
//! cert uploaded or ACME-issued after boot stayed invisible to the
//! worker's TLS stack until a full process restart - the `domain_count`
//! on the worker's `CertResolver` stayed at the boot snapshot.
//!
//! These tests exercise `handle_config_reload_commit` directly with
//! a populated in-memory store and a fresh empty `CertResolver`, then
//! assert the resolver picked up the cert. If the v1.5.2 fix is ever
//! reverted (or a future refactor of the commit handler drops the
//! `reload_cert_resolver` call), these tests fail with a clear
//! "domain_count is 0, expected 1" message that names the regression.

use std::sync::Arc;

use arc_swap::ArcSwap;
use chrono::{Duration, Utc};
use lorica_command::{command, Command, CommandType, ConfigReloadCommit, GenerationGate, IncomingCommand};
use lorica_config::models::{Certificate, LoadBalancing, WafMode};
use lorica_config::{store::new_id, ConfigStore};
use lorica_tls::cert_resolver::CertResolver;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair};
use tokio::sync::Mutex;

use super::{
    handle_config_reload_commit, PendingProxyConfig, ProxyConfig, ProxyConfigGlobals,
};
use crate::reload::PreparedReload;

/// Generate a real self-signed cert PEM pair via `rcgen` 0.13 so the
/// `CertResolver` can actually parse it (`build_certified_key` rejects
/// invalid PEM at reload time, so a placeholder string would not
/// exercise the reload path).
fn make_self_signed_pem(cn: &str) -> (String, String) {
    let mut params = CertificateParams::new(vec![cn.to_string()])
        .expect("rcgen::CertificateParams::new for test cert");
    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, cn);
    params.distinguished_name = dn;
    let key = KeyPair::generate().expect("rcgen::KeyPair::generate");
    let cert = params.self_signed(&key).expect("rcgen self_signed");
    (cert.pem(), key.serialize_pem())
}

/// Build a minimal Route shape attached to a certificate so
/// `reload_cert_resolver` keeps the cert (it filters by
/// `routes.certificate_id` so an unreferenced cert is intentionally
/// dropped from the resolver).
fn make_route_referencing(route_id: &str, hostname: &str, cert_id: &str) -> lorica_config::models::Route {
    let now = Utc::now();
    lorica_config::models::Route {
        id: route_id.into(),
        hostname: hostname.into(),
        path_prefix: "/".into(),
        certificate_id: Some(cert_id.into()),
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
        security_headers: "moderate".to_string(),
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
        path_rules: vec![],
        return_status: None,
        sticky_session: false,
        basic_auth_username: None,
        basic_auth_password_hash: None,
        stale_while_revalidate_s: 10,
        stale_if_error_s: 60,
        retry_on_methods: vec![],
        maintenance_mode: false,
        error_page_html: None,
        cache_vary_headers: vec![],
        header_rules: vec![],
        traffic_splits: vec![],
        forward_auth: None,
        mirror: None,
        response_rewrite: None,
        mtls: None,
        rate_limit: None,
        geoip: None,
        bot_protection: None,
        group_name: String::new(),
        created_at: now,
        updated_at: now,
    }
}

#[tokio::test]
async fn handle_config_reload_commit_reloads_cert_resolver() {
    // === Arrange : populated store + fresh empty resolver ===
    let store = Arc::new(Mutex::new(
        ConfigStore::open_in_memory().expect("in-memory store"),
    ));
    let (cert_pem, key_pem) = make_self_signed_pem("test.local");
    let cert_id = new_id();
    let route_id = new_id();
    let now = Utc::now();
    {
        let s = store.lock().await;
        let cert = Certificate {
            id: cert_id.clone(),
            domain: "test.local".into(),
            san_domains: vec![],
            fingerprint: "sha256:test".into(),
            cert_pem,
            key_pem,
            issuer: "Lorica Test".into(),
            not_before: now,
            not_after: now + Duration::days(365),
            is_acme: false,
            acme_auto_renew: false,
            created_at: now,
            acme_method: None,
            acme_dns_provider_id: None,
        };
        s.create_certificate(&cert).expect("seed cert");
        let route = make_route_referencing(&route_id, "test.local", &cert_id);
        s.create_route(&route).expect("seed route");
    }
    let cert_resolver = Arc::new(CertResolver::new());
    assert_eq!(
        cert_resolver.domain_count(),
        0,
        "fresh CertResolver must start empty (sanity)"
    );

    let proxy_config = Arc::new(ArcSwap::from_pointee(ProxyConfig::from_store(
        vec![],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals::default(),
    )));

    // === Arrange : a pending PreparedReload for generation 1 ===
    let prepared = PreparedReload {
        config: ProxyConfig::from_store(
            vec![],
            vec![],
            vec![],
            vec![],
            ProxyConfigGlobals::default(),
        ),
        connection_allow_cidrs: vec![],
        connection_deny_cidrs: vec![],
        mtls_fingerprint_drift: None,
    };
    let pending = Arc::new(parking_lot::Mutex::new(Some(PendingProxyConfig {
        generation: 1,
        prepared,
    })));
    let gate = Arc::new(GenerationGate::new());

    // === Arrange : a ConfigReloadCommit RPC for generation 1 ===
    let cmd = Command::rpc(
        42, // sequence
        CommandType::ConfigReloadCommit,
        command::Payload::ConfigReloadCommit(ConfigReloadCommit { generation: 1 }),
    );
    let (tx_out, mut rx_out) = tokio::sync::mpsc::channel(8);
    let inc = IncomingCommand::for_test(cmd, tx_out);

    // === Act : drive the worker-side commit handler ===
    handle_config_reload_commit(
        inc,
        &proxy_config,
        &pending,
        None,
        &gate,
        0, // worker_id
        &store,
        &cert_resolver,
    )
    .await;

    // === Assert : the v1.5.2 fix is in place ===
    // Pre-fix : `domain_count() == 0` (the cert sat in the store, the
    // route referenced it, but the commit handler never reloaded the
    // resolver, so the worker's TLS stack never saw it).
    // Post-fix : `domain_count() == 1` (the cert is loaded and
    // resolvable for `test.local`).
    assert_eq!(
        cert_resolver.domain_count(),
        1,
        "v1.5.2 audit M-22 regression : `handle_config_reload_commit` must call \
         `reload_cert_resolver` after committing the prepared config so workers \
         pick up newly-installed / ACME-renewed certs without a process restart"
    );

    // === Assert : the supervisor saw an OK reply (audit H-5 pin) ===
    // The fix replies BEFORE the cert reload runs (because OCSP fetches
    // can blow the supervisor's 500 ms commit deadline) ; the test
    // would deadlock on rx_out.recv() if reply order regressed.
    let envelope = rx_out
        .recv()
        .await
        .expect("commit handler must reply on the rpc channel");
    let response = match envelope.kind {
        Some(lorica_command::envelope::Kind::Response(r)) => r,
        other => panic!("expected Response envelope, got {other:?}"),
    };
    assert_eq!(
        response.sequence, 42,
        "reply must carry the originating sequence so the supervisor's request future resolves"
    );
    assert_eq!(
        response.status,
        lorica_command::ResponseStatus::Ok as i32,
        "commit must reply Ok on the happy path ; got status {} with msg `{}`",
        response.status,
        response.message,
    );
}

#[tokio::test]
async fn handle_config_reload_commit_unreferenced_cert_stays_unloaded() {
    // Counter-test : a cert that exists in the store but is NOT
    // referenced by any route should NOT end up in the resolver after
    // commit. This pins the existing `reload_cert_resolver` filter
    // (`active_cert_ids` from `list_routes`) so a future attempt to
    // "load all certs unconditionally" cannot accidentally tip a
    // disabled or stale cert into the live TLS stack.
    let store = Arc::new(Mutex::new(
        ConfigStore::open_in_memory().expect("in-memory store"),
    ));
    let (cert_pem, key_pem) = make_self_signed_pem("orphan.local");
    let cert_id = new_id();
    let now = Utc::now();
    {
        let s = store.lock().await;
        let cert = Certificate {
            id: cert_id.clone(),
            domain: "orphan.local".into(),
            san_domains: vec![],
            fingerprint: "sha256:orphan".into(),
            cert_pem,
            key_pem,
            issuer: "Lorica Test".into(),
            not_before: now,
            not_after: now + Duration::days(365),
            is_acme: false,
            acme_auto_renew: false,
            created_at: now,
            acme_method: None,
            acme_dns_provider_id: None,
        };
        s.create_certificate(&cert).expect("seed orphan cert");
        // No route referencing this cert.
    }
    let cert_resolver = Arc::new(CertResolver::new());
    let proxy_config = Arc::new(ArcSwap::from_pointee(ProxyConfig::from_store(
        vec![],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals::default(),
    )));
    let prepared = PreparedReload {
        config: ProxyConfig::from_store(
            vec![],
            vec![],
            vec![],
            vec![],
            ProxyConfigGlobals::default(),
        ),
        connection_allow_cidrs: vec![],
        connection_deny_cidrs: vec![],
        mtls_fingerprint_drift: None,
    };
    let pending = Arc::new(parking_lot::Mutex::new(Some(PendingProxyConfig {
        generation: 1,
        prepared,
    })));
    let gate = Arc::new(GenerationGate::new());
    let cmd = Command::rpc(
        7,
        CommandType::ConfigReloadCommit,
        command::Payload::ConfigReloadCommit(ConfigReloadCommit { generation: 1 }),
    );
    let (tx_out, mut rx_out) = tokio::sync::mpsc::channel(8);
    let inc = IncomingCommand::for_test(cmd, tx_out);

    handle_config_reload_commit(
        inc,
        &proxy_config,
        &pending,
        None,
        &gate,
        0,
        &store,
        &cert_resolver,
    )
    .await;

    assert_eq!(
        cert_resolver.domain_count(),
        0,
        "unreferenced cert must not be loaded by the resolver - the active-cert filter \
         (`reload_cert_resolver` keeps only certs referenced by `routes.certificate_id`) \
         must hold across the commit path"
    );
    let _ = rx_out.recv().await;
}

#[tokio::test]
async fn handle_config_reload_commit_stale_generation_replies_error_and_skips_reload() {
    // The commit handler must reject a stale generation (one already
    // observed) without touching the cert resolver. This pins the
    // `gate.observe_commit` short-circuit so a duplicate or out-of-
    // order commit cannot ArcSwap stale state on top of fresher state.
    let store = Arc::new(Mutex::new(
        ConfigStore::open_in_memory().expect("in-memory store"),
    ));
    let (cert_pem, key_pem) = make_self_signed_pem("test.local");
    let cert_id = new_id();
    let route_id = new_id();
    let now = Utc::now();
    {
        let s = store.lock().await;
        let cert = Certificate {
            id: cert_id.clone(),
            domain: "test.local".into(),
            san_domains: vec![],
            fingerprint: "sha256:test".into(),
            cert_pem,
            key_pem,
            issuer: "Lorica Test".into(),
            not_before: now,
            not_after: now + Duration::days(365),
            is_acme: false,
            acme_auto_renew: false,
            created_at: now,
            acme_method: None,
            acme_dns_provider_id: None,
        };
        s.create_certificate(&cert).expect("seed cert");
        let route = make_route_referencing(&route_id, "test.local", &cert_id);
        s.create_route(&route).expect("seed route");
    }
    let cert_resolver = Arc::new(CertResolver::new());
    let proxy_config = Arc::new(ArcSwap::from_pointee(ProxyConfig::from_store(
        vec![],
        vec![],
        vec![],
        vec![],
        ProxyConfigGlobals::default(),
    )));

    // Advance the gate to gen 5 so a commit for gen 1 is stale.
    let gate = Arc::new(GenerationGate::new());
    gate.observe(5).expect("seed gate to gen 5");

    let pending = Arc::new(parking_lot::Mutex::new(Some(PendingProxyConfig {
        generation: 1,
        prepared: PreparedReload {
            config: ProxyConfig::from_store(
                vec![],
                vec![],
                vec![],
                vec![],
                ProxyConfigGlobals::default(),
            ),
            connection_allow_cidrs: vec![],
            connection_deny_cidrs: vec![],
            mtls_fingerprint_drift: None,
        },
    })));

    let cmd = Command::rpc(
        99,
        CommandType::ConfigReloadCommit,
        command::Payload::ConfigReloadCommit(ConfigReloadCommit { generation: 1 }),
    );
    let (tx_out, mut rx_out) = tokio::sync::mpsc::channel(8);
    let inc = IncomingCommand::for_test(cmd, tx_out);

    handle_config_reload_commit(
        inc,
        &proxy_config,
        &pending,
        None,
        &gate,
        0,
        &store,
        &cert_resolver,
    )
    .await;

    assert_eq!(
        cert_resolver.domain_count(),
        0,
        "stale-generation commit must NOT touch the cert resolver - skipping the gate \
         check would let an out-of-order commit replace a fresher resolver state with \
         the stale snapshot it carries"
    );
    let envelope = rx_out
        .recv()
        .await
        .expect("stale commit must still reply (with an error)");
    let response = match envelope.kind {
        Some(lorica_command::envelope::Kind::Response(r)) => r,
        other => panic!("expected Response, got {other:?}"),
    };
    assert_eq!(
        response.status,
        lorica_command::ResponseStatus::Error as i32,
        "stale generation must reply with an error so the supervisor can retry"
    );
}
