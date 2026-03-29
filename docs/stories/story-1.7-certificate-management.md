# Story 1.7: Dashboard - Certificate Management

**Epic:** [Epic 1 - Foundation](../prd/epic-1-foundation.md)
**Status:** Draft
**Priority:** P0
**Depends on:** Story 1.5

---

As an infrastructure engineer,
I want to manage TLS certificates from the dashboard,
so that I can upload, monitor, and replace certificates without SSH.

## Acceptance Criteria

1. Certificates list screen: domain, issuer, expiration date, status (valid/expiring/expired)
2. Certificate upload: PEM file upload (cert + key) via dashboard
3. Certificate detail: full certificate chain display, associated routes
4. Expiration thresholds: warning at 30 days, critical at 7 days (configurable)
5. Self-signed certificate generation: prompt with preference memory (never/always/once)
6. Certificate deletion: confirmation with impact display (which routes affected)

## Integration Verification

- IV1: Uploaded certificate is usable for TLS termination on configured routes
- IV2: Expiration status is calculated correctly based on current date
- IV3: Certificate deletion blocks if routes still reference it (or shows warning)

## Tasks

- [ ] Build certificates list screen with expiry status indicators
- [ ] Implement PEM file upload component (cert + key)
- [ ] Build certificate detail view (chain, domains, expiry, associated routes)
- [ ] Implement expiration threshold configuration
- [ ] Implement self-signed cert generation with preference memory UI
- [ ] Build deletion flow with impact display
- [ ] Wire all operations to REST API
- [ ] Test certificate upload and TLS termination end-to-end

## Dev Notes

- Expiration status colors: green (> 30 days), orange (7-30 days), red (< 7 days or expired)
- Self-signed cert preference memory: never / always / once - stored in UserPreference table
- Certificate detail should parse and display the PEM to show chain info
- Deletion should show which routes would lose their TLS certificate
