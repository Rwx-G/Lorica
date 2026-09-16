# Story 10.5: GitLab OIDC ID Tokens (Optional Authentication Mode)

**Epic:** [Epic 10 - Conditional Request Capture & CI Automation API (v1.8.0)](../prd/epic-10-v1.8.0.md)
**Status:** Review
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

- [x] Add `jsonwebtoken` to the workspace, pinned, with a comment in `Cargo.toml` naming the approval and the story. Run `cargo audit` and `cargo deny` before anything else.
- [x] AC #1: the issuer model, its migration, its management API and its audit rows.
- [x] AC #2: the verifier, the pinned algorithm, the JWKS cache and its two refresh triggers.
- [x] AC #3: the claim-derived identity on the environment row, and the ownership rule re-based on `project_path`.
- [x] AC #4: the bounded replay set with its eviction counter.
- [x] AC #5: the fail-closed paths.
- [x] AC #6: `docs/automation.md`.
- [ ] The e2e OIDC fixture and IV1 to IV5. IV1 to IV5 are covered in-process by the `lorica-api` suite against a mock issuer (see Completion Notes); the Docker e2e fixture and its profile wiring are not done.
- [x] Gates: the three CI clippy commands with `RUSTFLAGS=-D warnings`, every Rust suite, `cargo audit`. No dashboard page was added, so the frontend gates were not touched.

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

- 2026-09-17: `jsonwebtoken` 11.1 needs exactly one crypto backend feature. `rust_crypto` pulls the `rsa` crate, which carries the open RUSTSEC-2023-0071 (Marvin) advisory with no patched release and would fail the `cargo audit` gate; `aws_lc_rs` was chosen, and `aws-lc-rs` 1.18.1 was already in the lockfile through the `route53` feature path. `cargo audit` after the add: 650 crates scanned, only the two pre-existing allowed `unmaintained` warnings (`derivative` via lorica-core, `rustls-pemfile` via lorica-tls), neither in the new tree. `cargo deny check advisories` fails on those same two pre-existing unmaintained crates, unrelated to this story.
- 2026-09-17: the two IV4 tests were written first and run against a stub verifier that refused everything as `no_issuer`; both failed (`left: Some(NoIssuer)`, expected `WrongAlg`) before the verifier existed, then passed with it.
- 2026-09-17: `jsonwebtoken` validates `exp`/`nbf` against the system clock, not a caller-supplied instant, so the tests mint tokens against the real clock and pass a synthetic `now` only to the JWKS cache and the replay set. `iat` is checked by the verifier itself, against the caller's `now`.
- 2026-09-17: generating one RSA-2048 key per unknown `kid` made the thousand-kid test take 137 s; it now signs a thousand tokens with one unpublished key and varies only the header's `kid`, which is what the cache actually sees.
- 2026-09-17: the environment-binding test first minted three tokens from one claims object, so the second request was refused as `replayed`; a test token is a job, and a job mints once.

### Completion Notes

- Verifier: `lorica-api/src/automation/oidc/` (`mod.rs` verification and the GitLab slug rule, `jwks.rs` the cache and the HTTPS fetcher, `replay.rs` the bounded set, `test_support.rs` the mock issuer shared by every suite). RS256 is pinned twice: by string comparison on the header's `alg` before any key lookup, and in the `Validation.algorithms` list handed to the library.
- The bearer gate picks the mode by shape (`parse_automation_token` first, then the three-segment JWT test), peeks `aud` without verification only to select the issuer entries, reads those entries from the store on every request, and answers one 401 body for every refusal on either path. The precise reason travels to the audit layer through the write-once `PrincipalSlot` and lands in the `reason` field of the `automation.request.unauthenticated` row.
- `AutomationPrincipal` became credential-agnostic (kind, principal, grant id, grant fields, optional `pipeline`, optional required environment slug); the environment handlers no longer touch a token row. `whoami` reports `kind` and `pipeline`.
- Issuer entries do not replicate, asserted by `oidc_issuers_stay_out_of_the_canonical_blob`. Migration 59 creates `oidc_issuers` and adds `automation_environments.pipeline_json`.
- The GitLab environment slug rule (`Gitlab::Slug::Environment`) is reimplemented in `gitlab_environment_slug`: lowercase, non-alphanumerics to `-`, `env-` prefix when not starting with a letter, squeezed dashes, and for any name that is not already a slug or exceeds 24 characters, the first 17 characters plus `-` plus six base-36 digits of the SHA-256 of the name. The suffix arithmetic is derived from the Ruby source and tested for shape, determinism and distinctness, not against a value captured from a live GitLab; a mismatch would surface as a 403 naming both the sent name and the expected slug on the first protected deployment.
- IV1 to IV5 hold in-process: `a_well_formed_token_is_accepted_and_its_claims_become_the_identity`, `each_claim_failure_is_refused_with_its_own_reason`, `a_replayed_jti_is_refused_and_a_mismatch_does_not_consume_it` (IV1); `a_rotated_key_is_picked_up_on_the_next_unknown_kid_refresh`, `a_jwks_outage_keeps_cached_keys_until_the_interval_elapses_then_refuses` (IV2); `removing_an_issuer_refuses_the_next_id_token_immediately` (IV3); `an_hs256_token_signed_with_the_public_key_as_the_secret_is_refused_as_wrong_alg`, `a_token_with_alg_none_is_refused_as_wrong_alg` (IV4); `a_thousand_unknown_kids_produce_at_most_one_fetch_in_a_minute` (IV5). The Docker e2e fixture is not written.
- Not done: the e2e OIDC fixture in `tests-e2e-docker/`, a `lorica automation oidc-issuer` CLI subcommand, and a dashboard page. The management API is the registration surface.

## File List

- `lorica-api/Cargo.toml` (`jsonwebtoken` 11.1 on `aws_lc_rs`; `aws-lc-rs` as a dev-dependency for test key generation), `Cargo.lock`
- `lorica-config/src/models/oidc_issuer.rs` (new), `models/mod.rs`, `models/automation_token.rs` (`validate_hostname_pattern` shared), `models/automation_environment.rs` (`PipelineIdentity`, `pipeline`)
- `lorica-config/src/store/oidc_issuer.rs` (new), `store/mod.rs` (migration 59), `store/automation_environment.rs` (`pipeline_json`), `store/replica.rs`, `canonical.rs`, `tests.rs` (migration head 59)
- `lorica-api/src/automation/oidc/{mod,jwks,replay,test_support,tests}.rs` (new)
- `lorica-api/src/automation/{mod,auth,audit,router,environments}.rs`, `automation/environments/tests.rs`
- `lorica-api/src/oidc_issuers.rs`, `oidc_issuers/tests.rs` (new), `lib.rs`, `server.rs` (`AppState.oidc`, routes), `middleware/authorize.rs`, `metrics.rs`
- `lorica-api/src/{tests,acme/tests,automation_tokens/tests}.rs` (`AppState.oidc` in the harnesses)
- `lorica-api/openapi.yaml`, `lorica-api/openapi-automation.yaml`
- `lorica/src/startup/{single,supervisor}.rs`, `lorica/src/reload.rs`
- `docs/automation.md` (new, OIDC sections), `CHANGELOG.md`

## Change Log

- 2026-09-17: Implemented AC #1 to #6 with the in-process IV1 to IV5; the Docker e2e fixture is left open. Status to Review.
- 2026-09-16: Story drafted from the Epic 10 PRD. `jsonwebtoken` approved by the maintainer the same day, so the story is in scope. Added IV4 and IV5 and the bounded-set eviction counter in AC #4: the PRD describes the correct behaviour but asks nobody to prove the two failures that would be silent, algorithm confusion and an unbounded outbound fetch driven by unknown key ids.
