# Story 13.6: Packaging, End-to-End and the Operator Guide

**Epic:** [Epic 13 - AD CS Certificate Enrollment over CES (v1.10.0)](../prd/epic-13-v1.10.0.md)
**Status:** Approved
**Priority:** P0
**Author:** Romain G.
**Depends on:** Stories 13.1 to 13.5.
**Blocks:** the v1.10.0 release.

---

As an operator installing or upgrading Lorica,
I want the AD CS support to install like the rest of Lorica and to be proven against a real Kerberos exchange,
so that the first time it meets my authority is not the first time it meets Kerberos.

## Problem

Every piece of the epic is tested in isolation, and the client is
proven against an MIT KDC by the Story 13.1 harness. What is missing:
an install path that resolves the new runtime library the way an
operator's install does, a profile that drives the whole product
(authority, issuance from a route, renewal, adoption, breaker) against
a real Kerberos exchange, the operator guide, and the release check
against a real authority.

## Acceptance Criteria

These are the PRD's, unchanged. They are the contract.

1. **Package install checks.** The packages already declare the runtime library (Story 13.1 AC #1). The install and upgrade scripts (`dist/tests/deb-upgrade.sh`, `dist/tests/rpm-upgrade.sh`, the `test-rpm-install` job) install the new package through `apt-get install ./<deb>` and `dnf install ./<rpm>`, so the dependency is resolved the way an operator's install resolves it; legs that install the previous release keep `dpkg -i` and `rpm -ivh`. Each job checks that `ldd /usr/bin/lorica` resolves and that the binary starts.
2. **The e2e Docker suite gains an `adcs` profile** built on the Story 13.1 harness: it drives the management API through authority creation, connection test, issuance from a route, renewal, adoption, reversion and the D15 breaker.
3. **`docs/adcs.md`** complete, with the authority-side prerequisites, the network flows, troubleshooting by failing step (Story 13.1 AC #8), the supported-templates statement, and what Lorica refuses to support and why (NTLM, Basic, `/certsrv`, the `san:` attribute, wildcards). The cross-realm case is documented as observed in the spike and not covered by the e2e profile, whose single MIT realm does not reproduce an AD KDC's referral.
4. The threat model, OpenAPI and changelog deliverables of the epic are complete.
5. **Release check against a real authority**, run by the maintainer from the release candidate's `.deb` before the PR to `main`: connection test, one issuance of a test name, one "Renew now", one adoption. It confirms what the specifications left *unconfirmed* (the `To` header, the response shapes, the `KRB5_CONFIG` behaviour under the shipped unit) and the profile timeouts. The outcome is recorded in the story with every name replaced by a placeholder, and the test certificates are revoked by the authority's administrators afterwards. A failure here reopens the story that owns the failing step.

## Integration Verification

- IV1: The `adcs` profile passes, including the harness probe client being refused without a binding.
- IV2: A fresh install on Debian 13 and on the RHEL target, through `apt-get install` and `dnf install`, starts Lorica with no Kerberos package installed by hand.
- IV3: The release check of AC #5 passes.

## Tasks

### Lot 1: documentation

- [ ] `docs/adcs.md`: what it does, prerequisites on the authority side,
      Lorica-side setup (the settings tab), network and time,
      issuance, renewal, adoption, revert, the breaker and how to clear
      it, troubleshooting by failing step, supported and refused
      configurations with reasons, the `KRB5_CONFIG` and file
      capabilities caveat, the bot-protection cookie rotation on every
      certificate event, unbound certificates neither renewed nor
      purged, the mixed-version fleet upgrade order (followers first).
- [ ] `docs/security/threat-model.md`: the authority as an asset, the
      service account credential as a secret, mitigations (D5, D11,
      D13, D15) and D11's stated limit.
- [ ] `CHANGELOG.md` `[Unreleased]`: Added (AD CS enrollment), Security
      (what protects the credential and the authority), the new runtime
      library requirement.
- [ ] Links: README feature list, `docs/` index if one exists, the
      settings tab prerequisites section pointing at the guide.

### Lot 2: packaging and install checks

- [ ] AC #1 in the scripts and CI jobs.

### Lot 3: the `adcs` e2e profile

- [ ] A Lorica container joined to the harness network, driven through
      the management API: authority, test, issuance from a route,
      renewal, adoption, revert, breaker.

### Lot 4: release check (maintainer)

- [ ] AC #5, recorded here with placeholders.

## Dev Agent Record

### Debug Log

### Completion Notes

## File List

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-10-21 | 0.1 | Story drafted from the Epic 13 PRD. Status Approved (maintainer delegated the epic). | Romain G. |
