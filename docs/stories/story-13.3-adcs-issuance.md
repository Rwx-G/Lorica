# Story 13.3: Issuing a New Certificate

**Epic:** [Epic 13 - AD CS Certificate Enrollment over CES (v1.10.0)](../prd/epic-13-v1.10.0.md)
**Status:** Review
**Priority:** P0
**Author:** Romain G.
**Depends on:** Story 13.1 (`lorica-adcs`: `build_csr`, `enroll`,
`EnrollOutcome`), Story 13.2 (the authority, its store, the
single-flight guard and the helper that builds `CesParams` and the
`Secret`, the `cert_issuance_failed` alert type, the `adcs_*`
certificate columns).
**Blocks:** Story 13.4 (renewal reuses the issuance path) and Story 13.5
(adoption shows what issuance would request).

---

As an operator putting a service behind Lorica,
I want to obtain its certificate from my authority from the place I am already working,
so that I stop generating CSRs by hand and uploading what comes back.

## Problem

The client can enroll and the authority is configured, but nothing
turns an operator's intent ("this route needs a certificate") into a
CSR, a call and a stored certificate. Two entry points are wanted: the
certificate page, to prepare a certificate before the route exists, and
the route form, where the uncovered hostnames are already known.

## Decisions taken in this story

**One issuance function, two callers.** The certificate page and the
route form call the same endpoint; the route form only pre-fills it.
Story 13.4's renewal calls the same internal function with the
current certificate's SANs, subject and recorded template, so there is
one code path that builds a CSR and stores a result.

**The private key is generated, used and stored in one request.** The
key never leaves the API process before it is encrypted in the
certificate row, exactly as an uploaded certificate's key is stored
today.

**Pending stores nothing.** Per "Supported templates": the response is
shown, audited and alerted; the generated key is discarded.

## Acceptance Criteria

These are the PRD's, unchanged. They are the contract.

1. **Response shape** per D14: `CertificateResponse` gains the derived `source` (`acme`, `adcs`, `manual`) and the `adcs_*` fields, in `lorica-api` and `api.ts`.
2. **Issuance endpoint** `POST /api/v1/certificates/adcs`, Operator and above, taking SANs and optionally a template, key type and subject overrides. It checks every SAN against the allowlist **before** contacting the authority, and refuses the request naming the offending names. It refuses while the authority is in the failed state. It is rate-limited under a new `adcs_issue` bucket the size of `RL_ACME_PROVISION`, and it is single-flight with the other AD CS operations (D15).
3. **Certificate page**: an "AD CS" issuance form beside `CertificateAcmeForm.svelte`, SANs typed by the operator, defaults from the authority. A certificate issued here is not bound to a route; the renewal loop only renews bound certificates (`is_bound`), so it renews it once a route uses it. The form says so.
4. **Route form**: a new derived value, the route's hostname and aliases covered by **no stored certificate**, computed with `findUncoveredHostnames` (`lib/cert-san-match.ts`) over every certificate's `domain` plus `san_domains` (today `RoutingTab.svelte` only checks the selected certificate's `san_domains`), drives an "Issue from AD CS" action with those names pre-filled, wildcard aliases dropped (D5). A successful issuance sets the form's certificate selection; the binding persists when the route is saved. A route whose creation is cancelled leaves an unbound certificate, visible on the certificate page.
5. **Confirmation before every issuance**: a summary of the full request (template, key type, complete subject, every SAN) that the operator confirms. The confirmation is the dashboard's; the API documents that a call is an issuance.
6. **Outcomes**: issued, the certificate is stored with its chain, the subject **as issued** is displayed, the template OID observed in it is recorded, the issuing CA certificate is recorded on the authority if not yet known (D12), and the hot-swap path serves it; pending, nothing is stored and the request identifier is shown and audited ("Supported templates"); denied or fault, nothing is stored and the authority's message is shown.
7. **Audit and notification**: every issuance attempt is audited with SANs and outcome; a pending answer, a denial or a fault raises `cert_issuance_failed`.
8. **Automation plane and MCP**: no issuance path (D6). A test asserts that no automation route reaches the issuance endpoint.

## Integration Verification

- IV1: Issuing from the route form produces a certificate covering every hostname of the route and binds it, with no action besides saving the route.
- IV2: A SAN outside the allowlist, a wildcard SAN and a label-suffix lookalike (`evilcorp.example.org` against `corp.example.org`) are each refused with no request reaching the harness.

## Tasks

### Lot 1: the API

- [x] `CertificateResponse` gains `source` and the `adcs_*` fields
      (`lorica-api/src/certificates.rs`), `openapi.yaml` updated.
- [x] An internal `issue(store, authority, request) -> IssueOutcome`
      in the AD CS module that Story 13.4 reuses: SAN checks, subject
      assembly (authority defaults, request overrides, `CN` = first
      SAN), `build_csr` with the template's common name, `enroll`
      under the single-flight guard, outcome handling. On issued:
      store leaf, chain and encrypted key the way an uploaded
      certificate is stored, set `adcs_authority_id`, `adcs_template`,
      `adcs_template_oid` (read 1.3.6.1.4.1.311.21.7, fall back to
      1.3.6.1.4.1.311.20.2), `adcs_request_id`, `acme_auto_renew` from
      the authority's default; record the issuing CA certificate on
      the authority if absent; `notify_config_changed` so the resolver
      reloads.
- [x] `POST /api/v1/certificates/adcs`, Operator default role, `rl`
      bucket `adcs_issue` at `RL_ACME_PROVISION`, the failed-state
      refusal, the D15 credential classification on a ticket failure
      (same path as the connection test), audit, `cert_issuance_failed`
      on pending, denied and error outcomes.
- [x] Test: the automation route table does not reach the endpoint.
- [x] Tests with the client seam from Story 13.2: each outcome, the
      three IV2 refusals with no client call recorded, template OID
      extraction, issuing-CA recording.

### Lot 2: the dashboard

- [x] `api.ts`: types and call; `source` shown on the certificate list
      and detail.
- [x] `CertificateAdcsForm.svelte` beside the ACME form, with the
      confirmation summary and the unbound-certificate note.
- [x] `RoutingTab.svelte`: the "covered by no stored certificate"
      derived value, the "Issue from AD CS" action (hidden when no
      authority is configured or on a follower), the same confirmation
      component, setting `form.certificate_id` on success.
- [x] Vitest for the derived value (domain plus SANs, wildcards
      dropped), the confirmation summary, and the follower/no-authority
      hiding.

## Dev Notes

- The subject the authority returns may differ from the one sent:
  display the issued certificate's subject, never the request's.
- The key is generated by `lorica-adcs::build_csr` and returned as PEM;
  it goes straight into the same encrypted column uploaded keys use.
- `notify_config_changed` rotates the bot-protection HMAC on every
  certificate event (`rotate_bot_hmac_on_cert_event`), as ACME issuance
  does; documented in `docs/adcs.md` by Story 13.6.

## Dev Agent Record

### Debug Log

- 2026-10-21, Lot 1 (`b4c4d992`): `issue()` in `lorica-api/src/adcs/issue.rs`, reused by renewal; certificate responses gained `source` and an RFC 4514 `subject` (computed from the stored leaf). The automation certificate read exposes `source` and `subject` but not the internal `adcs_*` fields (orchestrator decision, applied in `b521711b`).
- 2026-10-21, Lot 2 (`cd03c7e1`, `061dbb8f`): the issuance form, the route-form action and the confirmation; the issued subject displayed once the API returned it.

### Completion Notes

- AC #1 to #8 met; IV1 covered by the RoutingTab test, IV2 by the issuance tests (zero client calls on each refusal).

## File List

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-10-21 | 0.1 | Story drafted from the Epic 13 PRD. Status Approved (maintainer delegated the epic). | Romain G. |
| 2026-10-21 | 0.2 | Lots implemented. Status Review. | Romain G. |
