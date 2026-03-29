# Story 1.7: Dashboard - Certificate Management

**Epic:** [Epic 1 - Foundation](../prd/epic-1-foundation.md)
**Status:** Review
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

- [x] Build certificates list screen with expiry status indicators
- [x] Implement PEM file upload component (cert + key)
- [x] Build certificate detail view (chain, domains, expiry, associated routes)
- [x] Implement expiration threshold configuration
- [x] Implement self-signed cert generation with preference memory UI
- [x] Build deletion flow with impact display
- [x] Wire all operations to REST API
- [x] Test certificate upload and TLS termination end-to-end

## Dev Notes

- Expiration status colors: green (> 30 days), orange (7-30 days), red (< 7 days or expired)
- Self-signed cert preference memory: never / always / once - stored in UserPreference table
- Certificate detail should parse and display the PEM to show chain info
- Deletion should show which routes would lose their TLS certificate

## File List

- `lorica-dashboard/frontend/src/lib/api.ts` - Added certificate CRUD API methods + types
- `lorica-dashboard/frontend/src/components/CertExpiryBadge.svelte` - Certificate expiry status badge component
- `lorica-dashboard/frontend/src/components/CertExpiryBadge.test.ts` - CertExpiryBadge tests (10 tests)
- `lorica-dashboard/frontend/src/routes/Certificates.svelte` - Certificate management page (list, upload, detail, edit, delete, self-signed, thresholds)
- `lorica-dashboard/frontend/src/routes/Dashboard.svelte` - Router wiring for /certificates
- `lorica-dashboard/frontend/src/lib/api.test.ts` - Added certificate API client tests (6 tests)

## Change Log

- Added CertExpiryBadge component with valid/warning/critical/expired states
- Added Certificates page with full CRUD: list, upload PEM, detail view, edit, delete with impact
- Added self-signed certificate generation with preference memory prompt (never/always/once)
- Added configurable expiration thresholds (default: 30d warning, 7d critical)
- Added certificate API client methods: getCertificate, createCertificate, updateCertificate, deleteCertificate
- Wired /certificates route in Dashboard router
- 16 new tests (10 CertExpiryBadge + 6 API client)
