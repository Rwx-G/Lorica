# Story 10.5: GitLab OIDC ID Tokens (Optional Authentication Mode)

**Epic:** [Epic 10 - Conditional Request Capture & CI Automation API (v1.8.0)](../prd/epic-10-v1.8.0.md)
**Status:** Draft
**Priority:** P1, the last story of the cycle
**Author:** Romain G.
**Depends on:** Story 10.3 (the listener and the scope model) and Story 10.4 (the resource whose ownership rule this story re-bases).
**Blocks:** nothing.

---

As a GitLab administrator,
I want pipelines to authenticate to Lorica with the job's own ID token instead of a long-lived shared secret,
so that no Lorica credential has to live in CI variables at all and the authorisation is bound to the project and environment that the job actually runs for.

## Dependency

This story needs a JWT library. `jsonwebtoken` is not in the workspace and
the project forbids adding a dependency without explicit approval.
**Approved by the maintainer on 2026-09-16**, so the story is in scope for
1.8.0. Had it been refused, Story 10.3's static tokens would have remained
the only mode, which the PRD records as a complete and shippable outcome.

## Problem

A Story 10.3 token is a long-lived shared secret sitting in a CI variable.
It is masked, it is scoped, and it is still a secret that outlives every
job that uses it, that a fork of the repository might reach, and that
nobody rotates. A GitLab job can instead present an ID token that the
instance signs, that lives for minutes, and that states which project,
which ref and which environment the job is actually running for.

That last part is what makes this more than a credential hygiene
improvement: the authorisation stops being "whoever holds this string" and
becomes "a job for project X deploying environment Y".

## What this changes that is not obvious

**The algorithm must never come from the token.** A JWT library that
validates with whatever `alg` the header claims is the oldest defect in
this family. The validation pins RS256 on the verifier side, and the test
for it presents a token signed `HS256` with the public key as the MAC
secret and asserts a refusal.

**An unknown `kid` is an outbound-fetch primitive.** Without a limit, a
caller sending tokens with random `kid` values drives one JWKS fetch each,
from Lorica to the issuer, at request rate. The refetch is capped at once
per minute regardless of how many unknown kids arrive.

**The replay set is bounded, and that bound is the point.** Remembering
every `jti` until its `exp` is correct until someone sends a million
tokens. It is the same stance as the capture buffers in Story 10.1: an
operator-facing feature must not become a memory-exhaustion primitive on a
node that also terminates production TLS.

**Globs are allowed on one claim and not the others.** `project_path`
takes a glob because a group of projects is a real authorisation unit.
`ref_protected`, `environment_protected` and `deployment_tier` are
booleans and enums whose whole value is being exact; a glob there would
silently widen a decision an operator believed they had narrowed.

**The issuer URL is operator-supplied but not untrusted.** Only a
SuperAdmin on the management API can register one, and it must be `https`.
The fetch reuses the existing `reqwest` client and the ACME TLS roots, and
does not follow a redirect to a different host, so a compromised or
mistyped issuer cannot turn the control plane into a probe of its own
network.

## Acceptance Criteria

1. **Trust configuration on the management API.** `POST /api/v1/automation/oidc-issuers` (SuperAdmin): `issuer` (must be `https`), `audience` (unique per Lorica instance), `jwks_url` (defaults to `<issuer>/oauth/discovery/keys`), `bound_claims` (exact-match map over `project_path`, `namespace_path`, `ref_protected`, `environment_protected`, `deployment_tier`, with glob support on `project_path` only), and the same `allowed_hostnames`, `allowed_backend_cidrs`, `max_ttl` and `scopes` as a static token. One issuer entry is one authorisation policy; several entries may share an issuer with different bound claims.

2. **Verification.** RS256 only, pinned on the verifier and never read from the token header. `iss`, `aud`, `exp`, `nbf` and `iat` checked with 60 s of skew. `kid` looked up in a JWKS cache refreshed every 6 hours, and on an unknown `kid` at most once per minute. Every `bound_claims` entry must match exactly. Any failure is 401 with a generic reason on the wire and the precise reason in the audit row.

3. **The token's claims become the environment's identity.** `project_path`, `ref`, `pipeline_id`, `job_id` and `user_login` are recorded on the environment row and in the audit trail. Story 10.4's ownership rule is enforced on `project_path` instead of the token name. A token bound to `environment_protected = true` cannot create an environment whose `name` does not equal the job's `environment` claim slug.

4. **Replay resistance.** `jti` is remembered until `exp` in a bounded in-memory set; a replayed token is 401 and audited. The bound is explicit, documented, and when it is reached the oldest entries are evicted and the eviction is counted, because a silent eviction would turn a full set into a replay window.

5. **Failure is closed.** A JWKS endpoint outage keeps already-cached keys working until their refresh interval elapses, then refuses. Removing an issuer entry refuses the next request immediately.

6. **Documentation.** `docs/automation.md` gains the GitLab job snippet (`id_tokens:` with `aud`), the issuer registration walk-through, and a "static token vs ID token" comparison so an operator picks a mode deliberately rather than by default.

## Integration Verification

- **IV1:** A token minted by a local OIDC fixture (the e2e profile ships a tiny issuer serving a JWKS) with matching bound claims creates an environment; the same token with `project_path` changed, with `aud` changed, expired, or presented twice is refused each time with a distinct audit reason.
- **IV2:** Rotating the fixture's signing key is picked up on the next unknown-`kid` refresh without a restart; a JWKS outage keeps cached keys working until the refresh interval, then fails closed.
- **IV3:** Removing the issuer entry on the management API makes the next ID-token request 401 immediately.
- **IV4:** A token whose header says `alg: HS256`, signed with the issuer's public key as the MAC secret, is refused. A token with `alg: none` is refused. Neither produces a successful verification under any configuration.
- **IV5:** A thousand tokens carrying distinct unknown `kid` values produce at most one JWKS fetch per minute, asserted on the fixture's request count.

## Tasks

- [ ] Add `jsonwebtoken` to the workspace, pinned, with a comment in `Cargo.toml` naming the approval and the story. Run `cargo audit` and `cargo deny` before anything else.
- [ ] AC #1: the issuer model, its migration, its management API and its audit rows.
- [ ] AC #2: the verifier, the pinned algorithm, the JWKS cache and its two refresh triggers.
- [ ] AC #3: the claim-derived identity on the environment row, and the ownership rule re-based on `project_path`.
- [ ] AC #4: the bounded replay set with its eviction counter.
- [ ] AC #5: the fail-closed paths.
- [ ] AC #6: `docs/automation.md`.
- [ ] The e2e OIDC fixture and IV1 to IV5.
- [ ] Gates: the three CI clippy commands with `RUSTFLAGS=-D warnings`, every Rust suite, `cargo audit`, the frontend three if the dashboard gains an issuer page.

## Dev Notes

### Order

The verifier first, alone, with IV4 written before it works. Everything
else in this story is plumbing around a decision that is either correct or
a complete authentication bypass, and it is the one part that should not
be reviewed alongside anything else.

### What this does not do

It does not replace static tokens. Both modes coexist, the scopes are the
same closed enum from Story 10.3, and an operator picks per issuer. A
deployment with no GitLab keeps the mode it has.

## Dev Agent Record

### Debug Log

(empty)

### Completion Notes

(empty)

## File List

Anticipated, to be corrected during implementation.

- `Cargo.toml` (workspace), `lorica-api/Cargo.toml`
- `lorica-config/src/models/oidc_issuer.rs`, `store/oidc_issuer.rs`
- `lorica-api/src/automation/oidc.rs` (new: verifier, JWKS cache, replay set)
- `tests-e2e-docker/` (the OIDC fixture and its profile wiring)
- `docs/automation.md`, `CHANGELOG.md`

## Change Log

- 2026-09-16: Story drafted from the Epic 10 PRD. `jsonwebtoken` approved by the maintainer the same day, so the story is in scope. Added IV4 and IV5 and the bounded-set eviction counter in AC #4: the PRD describes the correct behaviour but asks nobody to prove the two failures that would be silent, algorithm confusion and an unbounded outbound fetch driven by unknown key ids.
