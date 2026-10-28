# Story 13.4: Renewal

**Epic:** [Epic 13 - AD CS Certificate Enrollment over CES (v1.10.0)](../prd/epic-13-v1.10.0.md)
**Status:** Done
**Priority:** P0
**Author:** Romain G.
**Depends on:** Story 13.3 (the internal `issue()` with its in-place
update path), Story 13.2 (guard, breaker, alert types).
**Blocks:** Story 13.5 (adoption relies on renewal to take a
certificate over) and Story 13.6 (the e2e profile renews).

---

As an operator,
I want AD CS certificates renewed the way ACME ones are,
so that an internal certificate never expires because someone forgot it.

## Problem

`lorica-api/src/acme/renewal.rs` renews ACME certificates on a 12 h
tick on the control plane: `should_auto_renew` filters, `is_bound`
keeps unbound certificates out, `renew_with_method` dispatches, the
in-memory `RenewalLedger` holds cooldowns and an in-flight mark shared
with the dashboard's renew. Everything there is ACME-shaped, and
`renew_certificate_as` refuses non-ACME certificates. AD CS
certificates need the same window and binding rule, a different
dispatch, a different failure model (a credential failure stops all of
them at once), and no exposure to tokens.

## Decisions taken in this story

**Dispatch by derived source, beside the ACME code.** The ACME
predicates stay in `acme/renewal.rs` untouched so their tests stay
green unmodified; the loop gains an AD CS arm selected by
`Certificate::source()`.

**One ticket per tick is a property of the guard.** Every AD CS renewal
in a tick runs through the single-flight guard and the breaker; after
the first credential rejection the breaker is open and the remaining
renewals of the tick are refused before any KDC contact, which is what
"one ticket attempt per tick" requires on the failure path. On the
success path each renewal acquires its own ticket in its own memory
cache; that is one AS-REQ per renewal, accepted (renewals are rare) and
recorded here rather than optimised with a shared cache, which would
need a ticket to outlive an operation, against D3.

## Acceptance Criteria

These are the PRD's, unchanged. They are the contract.

1. **A source-dispatched renewal loop.** The loop in `lorica-api/src/acme/renewal.rs` gains an AD CS arm and a dispatch by derived source (D14), with the same renewal window and the same `is_bound` rule for both sources. The ACME predicates (`should_auto_renew`, `is_bound`, `cooldown_from_error`, `superseded_orphans`) stay in `acme/renewal.rs`, so ACME behaviour is unchanged and the existing tests in `acme/tests.rs` stay green unmodified.
2. **Renewal is in place**: same certificate id, route bindings kept, new key and new CSR, the SANs and subject of the current certificate reused, **the certificate's recorded template** used (the authority's template is only the default at issuance). It takes the `RenewalLedger` in-flight mark shared by the loop and the dashboard; a second concurrent request answers 409.
3. **D15 in the loop**: one ticket per authority per tick, single-flight with every other AD CS operation; a pre-authentication failure stops every AD CS renewal for the tick and puts the authority in the failed state.
4. **Pending**: a renewal answered as pending keeps the current certificate in service, stores nothing, and is handled as a failure under AC #5, naming the request identifier.
5. **Failures** keep the current certificate in service, back off per certificate for non-credential failures, and raise `cert_issuance_failed` naming the failing step, once per failure state rather than once per tick.
6. **Expiry alerts**: `check_cert_expiry` alerts on every certificate in its window and the loop sends its own `CertExpiring` for eligible ones. The story decides which one speaks for an AD CS certificate and asserts that an operator receives one alert per certificate per state, not two.
7. **Audit**: every renewal attempt, loop included, writes an audit row, the loop's with `AuditContext::node("adcs-renewal")`. Today only the manual path audits (`certificate.renew`); an AD CS loop renewal is an issuance at the authority and is audited as one.
8. **"Renew now"** on the dashboard for an AD CS certificate, Operator and above, under the D15 breaker. The automation plane and MCP get `adcs_renewal_not_on_automation_plane` per D6, with the three-plane tests.

## Integration Verification

- IV1: A bound certificate whose expiry falls inside the window is renewed by the loop against the harness, keeps its id and route bindings, carries a different public key and was requested with its recorded template.
- IV2: With a wrong password and five AD CS certificates in the window, one tick makes exactly one ticket attempt and produces one `adcs_authority_failed` notification; a "Renew now" during the failed state makes none.

## Tasks

### Lot 1: the loop and the manual path

- [x] AD CS eligibility (source AD CS, `acme_auto_renew`, inside the
      window, bound) beside `should_auto_renew`; dispatch in the loop;
      the AD CS arm calls `issue()` in-place mode with the current
      SANs, subject and `adcs_template`.
- [x] `RenewalLedger` in-flight mark around the AD CS arm and the
      manual path; 409 on overlap.
- [x] Breaker short-circuit inside a tick; per-certificate cooldown for
      non-credential failures, kept apart from the ACME rate-limit
      cooldown; one `cert_issuance_failed` per failure state.
- [x] `renew_certificate_as`: AD CS accepted for the dashboard caller,
      refused for any token caller (`RenewalBudget::PerCertificate`)
      after `guard.check`, error `adcs_renewal_not_on_automation_plane`;
      tests on the dashboard route, the automation route and the MCP
      tool.
- [x] Expiry alert decision (AC #6) and its test.
- [x] Audit rows for loop and manual renewals.

### Lot 2: the dashboard

- [x] "Renew now" offered for AD CS certificates (Operator and above,
      not on a follower, not while the authority is failed), outcomes
      and 409/504 shown as returned. Vitest.

## Dev Notes

- `issue()` from Story 13.3 already handles the in-place update; the
  loop must not create a new certificate row.
- `superseded_orphans` only purges ACME certificates; it stays so.
- Every certificate event rotates the bot-protection HMAC
  (`rotate_bot_hmac_on_cert_event`); AD CS renewal does the same as
  ACME renewal, documented by Story 13.6.

## Dev Agent Record

### Debug Log

- 2026-10-21, Lot 1 (`b521711b`): `renewal_tick` with an AD CS arm (`adcs/renew.rs`); the breaker ends the tick on a credential rejection or the failed state; other failures back the certificate off 24 h and alert once per failure state. `check_cert_expiry` speaks for AD CS expiry; the loop's `CertExpiring` stays ACME-only. Token callers get 403 `adcs_renewal_not_on_automation_plane`.
- 2026-10-21 (`2041aee4`): renewal keeps the current key type and size instead of the authority default, so a default change cannot turn an RSA certificate into ECDSA that a version 2 template rejects.
- 2026-10-21, Lot 2 (`061dbb8f`): Renew now for AD CS on the certificate list, behind a confirmation since a renewal is an issuance.

### Completion Notes

- AC #1 to #8 met; IV1 and IV2 covered by `adcs/renew/tests.rs`.

### After the epic audit

- AC #3: the decision above ("one ticket per tick is a property of the guard", one AS-REQ per successful renewal) is superseded. A `CesSession` acquires one ticket and one HTTPS client for the whole tick, so a tick acquires at most one ticket on the success path too; the ticket stays in a per-call memory cache dropped with the session, so it does not outlive the tick (D3).
- AC #1: the loop runs the ACME arm first, re-reads each AD CS certificate before renewing it (one deleted, reverted, switched to auto-renew off, unbound or already renewed since selection is skipped), and ends the tick on any authority-wide failure (ticket, KDC, TLS, SPNEGO, mutual authentication, timeout); per-certificate back-off is kept for outcomes that concern one request. A busy guard makes the tick wait and retry instead of giving up.
- AC #2: renewal keeps the current key type and size; a template no longer in the authority's allowlist (D17) is refused before the authority is contacted.
- AC #7: a renewal that fails before reaching the authority still writes its audit row.
- Every renewal path is refused at the `krb5_conf` step when the process runs with `AT_SECURE` set (Story 13.2).
- The PRD records the epic-wide deviations in "Delivery notes (v1.10.0)".

## File List

- `lorica-api/src/adcs/renew.rs`, `lorica-api/src/adcs/renew/tests.rs`, `lorica-api/src/adcs/{issue,runtime}.rs`,
  `lorica-api/src/adcs/issue/tests.rs`, `lorica-api/src/adcs.rs`
- `lorica-api/src/acme/{mod,renewal}.rs`, `lorica-api/src/automation/{read,redact,write}.rs`,
  `lorica-api/src/automation/read/plane_tests.rs`, `lorica-mcp/src/tools.rs`
- `lorica-api/openapi.yaml`, `lorica-api/openapi-automation.yaml`
- `lorica-dashboard/frontend/src/components/certificates/{CertificateList,CertificateDetail}.svelte`,
  `lib/adcs-issuance.{ts,test.ts}`, `lib/api.ts`, `routes/Certificates.{svelte,test.ts}`

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-10-21 | 0.1 | Story drafted from the Epic 13 PRD. Status Approved (maintainer delegated the epic). | Romain G. |
| 2026-10-21 | 0.2 | Lots implemented. Status Review. | Romain G. |
| 2026-10-27 | 0.3 | Audit changes recorded (session per tick, re-read before renewing, tick ends on authority-wide failures), File List filled. Status Done. | Romain G. |
