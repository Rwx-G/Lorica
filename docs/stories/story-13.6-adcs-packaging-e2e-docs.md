# Story 13.6: Packaging, End-to-End and the Operator Guide

**Epic:** [Epic 13 - AD CS Certificate Enrollment over CES (v1.10.0)](../prd/epic-13-v1.10.0.md)
**Status:** Done
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

- [x] `docs/adcs.md`: what it does, prerequisites on the authority side,
      Lorica-side setup (the settings tab), network and time,
      issuance, renewal, adoption, revert, the breaker and how to clear
      it, troubleshooting by failing step, supported and refused
      configurations with reasons, the `KRB5_CONFIG` and file
      capabilities caveat, the bot-protection cookie rotation on every
      certificate event, unbound certificates neither renewed nor
      purged, the mixed-version fleet upgrade order (followers first).
- [x] `docs/security/threat-model.md`: the authority as an asset, the
      service account credential as a secret, mitigations (D5, D11,
      D13, D15) and D11's stated limit.
- [x] `CHANGELOG.md` `[Unreleased]`: Added (AD CS enrollment), Security
      (what protects the credential and the authority), the new runtime
      library requirement.
- [x] Links: README feature list, `docs/` index if one exists, the
      settings tab prerequisites section pointing at the guide.

### Lot 2: packaging and install checks

- [x] AC #1 in the scripts and CI jobs.

### Lot 3: the `adcs` e2e profile

- [x] A Lorica container joined to the harness network, driven through
      the management API: authority, test, issuance from a route,
      renewal, adoption, revert, breaker.

### Lot 4: release check (maintainer)

- [x] AC #5, recorded here with placeholders.

## Dev Agent Record

### Debug Log

- 2026-10-21, Lot 1 (`8d548195`): `docs/adcs.md`, the threat model section, the changelog and the README feature list.
- 2026-10-21, Lots 2 and 3 (`95e02a03`): the install and upgrade checks install the new package through `apt-get install` and `dnf install` and fail on an unresolved library of `lorica` or `lorica-mcp`; the upgrade scripts install the new package's dependencies before running its CLI from the extracted copy. The `adcs` e2e profile (`tests-e2e-docker/test-runner/run-adcs-smoke.sh`) drives a real Lorica against the Story 13.1 harness through authority, connection test, issuance from a route served over TLS, renewal, adoption and revert, the breaker, and the unbound probe.
- After the epic audit (`a541f687`): CI runs the Kerberos harness in its own job. `docs/adcs.md` gained D16 to D18, the error-code table tested against `ADCS_CODES`, and the accepted residual risks; the `KRB5_CONFIG` caveat now says Lorica detects `AT_SECURE` and refuses every AD CS operation rather than relying on the documentation alone.

### Completion Notes

- AC #1 to #4 met; IV1 and IV2 covered by the `adcs` profile and the deb and rpm install jobs.
- AC #5 and IV3 passed on 2026-10-27. The maintainer ran the release check against a production AD CS authority (CES in Kerberos mode, Extended Protection Required, NTLM refused, service account in a child domain of the authority's forest) from a `.deb` built at `1472df25` before the version bump, on a Debian 13 host with nothing Kerberos configured by hand. Connection test ok; a certificate issued for a test name under the allowed suffix, bound to a route and served correctly; "Renew now" replaced it in place and the new certificate was served; the maintainer reported the remaining steps (adoption) working. This confirms against a real authority what the specifications left unconfirmed: the request envelope and `To` header, the template carried as a CSR attribute, the response and CMC chain shapes, the RFC 5929 binding with the authority's certificate, and `KRB5_CONFIG` honoured under the shipped unit. The test certificates are to be revoked by the authority's administrators. Names of the deployment are deliberately not recorded.
- The PRD records the epic-wide deviations in "Delivery notes (v1.10.0)".

## File List

- `docs/adcs.md`, `docs/security/threat-model.md`, `CHANGELOG.md`, `README.md`
- `.github/workflows/ci.yml`, `dist/tests/deb-upgrade.sh`, `dist/tests/rpm-upgrade.sh`
- `tests-e2e-docker/adcs/ces/{harness_ca,server}.py`, `tests-e2e-docker/docker-compose.yml`, `tests-e2e-docker/run.sh`,
  `tests-e2e-docker/test-runner/Dockerfile`, `tests-e2e-docker/test-runner/run-adcs-smoke.sh`

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-10-21 | 0.1 | Story drafted from the Epic 13 PRD. Status Approved (maintainer delegated the epic). | Romain G. |
| 2026-10-27 | 0.2 | Lots 1 to 3 delivered and recorded; AC #5 (release check) pending with the maintainer. Status Review. | Romain G. |
| 2026-10-27 | 0.3 | Release check against a real authority passed (AC #5, IV3). Status Done. | Romain G. |
