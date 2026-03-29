# Story 2.3: Certificate Hot-Swap

**Epic:** [Epic 2 - Resilience](../prd/epic-2-resilience.md)
**Status:** Draft
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

- [ ] Implement SNI trie data structure with wildcard support
- [ ] Implement certificate index (domain -> sorted certs by expiry)
- [ ] Implement ResolvesServerCert trait for rustls integration
- [ ] Implement add/remove/replace operations with atomic semantics
- [ ] Propagate cert changes through command channel to workers
- [ ] Verify existing connections are not interrupted
- [ ] Write tests for wildcard matching
- [ ] Write tests for cert fallback on removal
- [ ] Write tests for hot-swap under load

## Dev Notes

- Pattern inspired by Sozu's CertificateResolver (concepts only)
- Trie supports exact match and wildcard (*.example.com)
- Certificate storage protected by Mutex for thread-safe access within each worker
- rustls ResolvesServerCert trait is called during TLS handshake to select cert
