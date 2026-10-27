# Story 13.5: Adopting Certificates Issued Before Lorica Could

**Epic:** [Epic 13 - AD CS Certificate Enrollment over CES (v1.10.0)](../prd/epic-13-v1.10.0.md)
**Status:** Done
**Priority:** P1
**Author:** Romain G.
**Depends on:** Story 13.2 (the issuing CA certificate on the
authority), Story 13.3 (template OID extraction), Story 13.4 (renewal
takes the adopted certificate over).
**Blocks:** Story 13.6 (the e2e profile adopts and reverts).

---

As an operator who has been issuing certificates by hand,
I want Lorica to recognise the ones my authority issued and take them over,
so that upgrading Lorica ends the manual work instead of adding a second process next to it.

## Problem

Certificates issued by hand before this release sit in Lorica as manual
uploads. The upgrade leaves them alone (D9). Taking them over must be
offered, never imposed, and must only offer certificates the
authority's issuing CA actually signed: matching on the issuer name
would let a sibling CA or a forged name in.

## Decisions taken in this story

**Detection is a pure read, computed on request.** Candidates are
derived from `list_certificates` and the authority's issuing CA
certificate each time the page asks; nothing is stored about a
candidate, so there is no state to keep in sync when certificates or
the CA change.

**Signature verification with what the tree already has.** The leaf's
signature is checked against the issuing CA certificate's public key
with `x509-parser`'s verification (the `verify` feature is enabled
workspace-wide since `rcgen`'s `aws_lc_rs` backend pulled it in, Story
13.1); if that is not available for a key type, `ring` verifies the
TBS bytes directly. No new dependency.

## Acceptance Criteria

These are the PRD's, unchanged. They are the contract.

1. **Candidates** per D9: every manual certificate whose leaf is signed by the authority's **issuing CA certificate** (signature and authority key identifier) and whose SANs satisfy the allowlist. Detection runs when the issuing CA certificate is set or changes, and on demand. With no issuing CA certificate known yet, the page says how to provide one.
2. **The certificate page shows the candidates**, with individual and bulk adoption (`POST /api/v1/certificates/{id}/adcs/adopt`), Operator and above.
3. **The adoption summary** shows, per certificate, the SANs and subject that renewal will request (from the certificate, not from the authority's defaults), the template it was issued with (the OID of extension 1.3.6.1.4.1.311.21.7, or the name of 1.3.6.1.4.1.311.20.2 for a version 1 template, decoded as BMPString or UTF8String) next to the one observed on certificates Lorica issued with the authority's template ("unknown" when Lorica has issued none yet), with a warning when they differ, and the auto-renew setting.
4. **Adoption issues nothing.** It sets the `adcs_*` references. Renewal happens in the normal window, or immediately on "Renew now".
5. **Reverting to manual** is available on any AD CS certificate: it clears `adcs_authority_id`, Lorica stops renewing it and keeps the current certificate in service (distinct from auto-renew off, D14).
6. Audit for adoption and reversion, naming the certificates.

## Integration Verification

- IV1: A certificate signed by the issuing CA is offered; one signed by a sibling issuing CA under the same root is not; one signed by another chain with a forged identical issuer name is not.
- IV2: An adopted, bound certificate renews in place at its next window with its route bindings intact.

## Tasks

### Lot 1: the API

- [x] `GET /api/v1/adcs/adoption-candidates` (Viewer): candidates with
      SANs, subject, template identifier and comparison, auto-renew
      default; empty with a reason when no issuing CA certificate is
      known.
- [x] `POST /api/v1/certificates/{id}/adcs/adopt` (Operator):
      re-checks candidacy server-side, sets `adcs_authority_id`,
      `adcs_template` (the authority's template; the observed one is
      kept in `adcs_template_oid`), `acme_auto_renew` from the request
      or the authority default. Bulk adoption is the dashboard calling
      it per certificate.
- [x] `POST /api/v1/certificates/{id}/adcs/revert` (Operator): clears
      `adcs_authority_id`.
- [x] RBAC table, follower refusal, audit, `openapi.yaml`, tests
      including IV1's three certificates (generated: issuing CA, sibling
      CA under the same root, forged issuer name).

### Lot 2: the dashboard

- [x] The candidates banner and list on the certificate page, the
      adoption summary with the template warning, individual and bulk
      adopt, revert on AD CS certificates. Vitest.

## Dev Agent Record

### Debug Log

- 2026-10-21, Lot 1 (`2041aee4`): candidacy requires the issuer bytes, the signature (x509-parser `verify_signature`) and the key identifier to match the first certificate of the authority's issuing CA field. Adoption clears `adcs_request_id` so an adopted certificate does not count as observed issuance; 409 `adcs_not_configured` when no issuing CA is known; revert refused while a renewal of the certificate is in flight.
- 2026-10-21, Lot 2 (`90ba802d`): banner, adoption panel with per-certificate summary and bulk adoption, revert on the list.

### Completion Notes

- AC #1 to #6 met; IV1 and IV2 covered by `adcs/adopt/tests.rs`.

### After the epic audit

- AC #1: with no issuing CA known the listing and adoption answer `adcs_no_issuing_ca`, not `adcs_not_configured` (the Debug Log above records the first behaviour). Verdicts are cached per pair of digests (certificate PEM, issuing CA DER), and the listing does nothing on a follower.
- AC #5: a loop renewal already past selection re-reads the certificate before renewing it, so a reversion during the tick is honoured (Story 13.4).
- The PEM, key and domain of an AD CS certificate cannot be replaced through `PUT /api/v1/certificates/{id}` (409 `adcs_certificate_managed`), which would otherwise have put an unverified certificate under the authority without the adoption signature check; revert to manual first. Adopted certificates fall under D16 (key not downloadable).
- The PRD records the epic-wide deviations in "Delivery notes (v1.10.0)".

## File List

- `lorica-api/src/adcs/adopt.rs`, `lorica-api/src/adcs/adopt/tests.rs`, `lorica-api/src/adcs.rs`,
  `lorica-api/src/adcs/{renew,issue}.rs`, `lorica-api/src/adcs/renew/tests.rs`, `lorica-api/src/adcs/issue/tests.rs`,
  `lorica-api/src/certificates.rs`, `lorica-api/src/middleware/authorize.rs`, `lorica-api/src/server.rs`,
  `lorica-api/openapi.yaml`, `docs/adcs.md`
- `lorica-dashboard/frontend/src/components/certificates/AdcsAdoptionPanel.{svelte,test.ts}`,
  `components/certificates/CertificateList.svelte`, `components/certificates/CertificateSource.test.ts`,
  `lib/adcs-adoption.{ts,test.ts}`, `lib/api.ts`, `routes/Certificates.{svelte,test.ts}`, `test-adcs-fixtures.ts`

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-10-21 | 0.1 | Story drafted from the Epic 13 PRD. Status Approved (maintainer delegated the epic). | Romain G. |
| 2026-10-21 | 0.2 | Lots implemented. Status Review. | Romain G. |
| 2026-10-27 | 0.3 | Audit changes recorded (own code for an unknown issuing CA, verdict cache, managed PEM refusal), File List filled. Status Done. | Romain G. |
