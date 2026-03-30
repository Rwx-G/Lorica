# Story 2.3: Certificate Hot-Swap

**Epic:** [Epic 2 - Resilience](../prd/epic-2-resilience.md)
**Status:** Done
**Priority:** P1
**Depends on:** Story 2.2

---

As an infrastructure engineer,
I want to add, replace, and remove TLS certificates without any downtime,
so that certificate rotation is seamless.

## Acceptance Criteria

1. SNI trie for fast domain-to-certificate lookup (wildcard support)
2. Certificate index: multiple certs per domain, sorted by expiration
3. Add operation: new cert replaces shorter-lived certs automatically
4. Remove operation: fallback to longest-lived remaining cert
5. Replace operation: atomic delete + add
6. Changes propagated to workers via command channel
7. Active TLS connections continue with old cert until they close naturally

## Integration Verification

- IV1: New certificate is served to new connections within 1 second of upload
- IV2: Existing connections continue on old certificate without interruption
- IV3: Wildcard certificates match subdomains correctly

## Tasks

- [x] Implement SNI trie data structure with wildcard support
- [x] Implement certificate index (domain -> sorted certs by expiry)
- [x] Implement ResolvesServerCert trait for rustls integration
- [x] Implement add/remove/replace operations with atomic semantics
- [x] Propagate cert changes through command channel to workers
- [x] Verify existing connections are not interrupted
- [x] Write tests for wildcard matching
- [x] Write tests for cert fallback on removal
- [x] Write tests for hot-swap under load

## Dev Notes

- Pattern inspired by Sozu's CertificateResolver (concepts only)
- HashMap with wildcard fallback instead of trie - O(1) exact + O(1) wildcard
- Certificate storage uses arc-swap for lock-free reads during TLS handshake
- rustls ResolvesServerCert trait is called during TLS handshake to select cert
- Certs loaded from PEM strings in memory - no temporary files on disk

## Dev Agent Record

### Agent Model Used
Claude Opus 4.6

### Completion Notes
- `CertResolver` in lorica-tls/src/cert_resolver.rs implements `ResolvesServerCert`
- HashMap<domain, Vec<CertEntry>> with entries sorted by expiry (longest-lived first)
- Wildcard matching: exact lookup, then `*.parent.domain` fallback
- `reload()` method atomically swaps the entire cert map via arc-swap
- `TlsSettings::with_resolver()` added to lorica-core for dynamic cert selection
- Single-process mode loads all DB certs into resolver at startup
- Workers reload certs via existing ConfigReload command channel
- 6 new tests in lorica-tls, 228 total, 0 failures

### File List
- `lorica-tls/src/cert_resolver.rs` (new)
- `lorica-tls/src/lib.rs` (modified - add cert_resolver module + ResolvesServerCert export)
- `lorica-tls/Cargo.toml` (modified - add arc-swap dep)
- `lorica-tls/tests/test-cert.pem` (new - test fixture)
- `lorica-tls/tests/test-key.pem` (new - test fixture)
- `lorica-core/src/listeners/tls/rustls/mod.rs` (modified - CertSource enum, with_resolver)
- `lorica/Cargo.toml` (modified - add lorica-tls dep)
- `lorica/src/main.rs` (modified - use CertResolver, no more cert files on disk)

### Change Log
- feat(tls): add SNI-based CertResolver with wildcard support and hot-swap
- feat(tls): wire CertResolver into TLS listeners and replace file-based certs
