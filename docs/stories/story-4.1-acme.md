# Story 4.1: ACME / Let's Encrypt Integration

**Epic:** [Epic 4 - Production](../prd/epic-4-production.md)
**Status:** Done
**Priority:** P2
**Depends on:** Story 2.3

---

As an infrastructure engineer,
I want Lorica to automatically provision TLS certificates via Let's Encrypt,
so that I don't have to manage certificates manually.

## Acceptance Criteria

1. ACME client implementation (HTTP-01 challenge)
2. Opt-in per route: admin explicitly enables auto-TLS (consent-driven)
3. Automatic renewal before expiration (configurable threshold, default 30 days)
4. Renewal requires consent or pre-configured auto-approval preference
5. Fallback: if ACME fails, notify admin and continue with existing cert
6. Certificate storage in embedded database alongside manually uploaded certs
7. Dashboard shows ACME-managed vs manually-managed certificates

## Integration Verification

- IV1: ACME provisioning successfully obtains a certificate from Let's Encrypt staging
- IV2: Auto-renewal triggers at configured threshold
- IV3: ACME failure does not disrupt existing TLS termination

## Tasks

- [ ] Research Rust ACME crates (instant-acme, acme-lib)
- [ ] Implement ACME client with HTTP-01 challenge
- [ ] Integrate challenge response into proxy engine (/.well-known/acme-challenge/)
- [ ] Implement consent-driven opt-in per route
- [ ] Implement auto-renewal with configurable threshold
- [ ] Implement failure fallback with admin notification
- [ ] Store ACME certs in database with is_acme flag
- [ ] Update dashboard to show ACME vs manual certs
- [ ] Test against Let's Encrypt staging environment
- [ ] Write tests for renewal flow
- [ ] Write tests for failure fallback

## Dev Notes

- HTTP-01 challenge requires the proxy to serve a challenge token on port 80
- Consent-driven: ACME is never auto-enabled, admin must opt in per route
- Auto-renewal preference: never / always / ask each time
- ACME account key stored in database
- Test against staging (acme-staging-v02.api.letsencrypt.org) before production
