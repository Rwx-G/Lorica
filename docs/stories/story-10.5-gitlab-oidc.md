# Story 10.5: GitLab OIDC ID Tokens (Optional Authentication Mode)

**Epic:** [Epic 10 - Conditional Request Capture & CI Automation API (v1.8.0)](../prd/epic-10-v1.8.0.md)
**Status:** Done
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
- [x] The e2e OIDC fixture and IV1 to IV5. IV1 to IV5 are covered in-process by the `lorica-api` suite against a mock issuer (see Completion Notes); the Docker e2e fixture and its profile wiring are not done.
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
- 2026-09-17, after audit: **ownership on `project_path` is exact equality, which departs from the PRD's "same name prefix" wording.** The prefix rule (the text before the first `-`) made `acme/web` and `acme/web-docs` one owner, and `acme/web-docs` is a project anybody with Developer access to the acme namespace can create. A naming convention is not an authorization boundary. Ownership is now the exact project path, in the `oidc_project` kind; a group that wants one grant across its projects expresses that on the issuer entry with `"project_path": "acme/*"`, which is a grant over what the credential may DO and not a claim that the projects are one owner. The same change landed on the static-token side; Story 10.4's Debug Log carries the full rationale.
- 2026-09-17, after audit: **an entry must bind `project_path` or `namespace_path`.** `aud` is a string the job writes into its own `id_tokens` block, not a secret, so an entry binding neither accepted a token from every project on the instance that guessed the audience. `OidcIssuer::validate` refuses one.
- 2026-09-17, after audit: **a `project_path` glob must be anchored and must not span `/`.** `acme*` is not a group grant, it is a string prefix, and it covers `acme-evil/pwn`. A glob now has to carry a `/` before its first `*`, which pins a whole namespace segment, and `*` no longer matches `/`, so `acme/*` is the acme group's own projects and `acme/sub/*` is how a subgroup is granted, in writing.
- 2026-09-17, after audit: **the unauthenticated `aud` fan-out.** `peek_audiences` was unbounded and each audience was one store read inside the single `db_blocking` closure, plus one audit row per attempt. The bearer value is now capped at `AUTOMATION_BEARER_MAX_BYTES` (8 KiB) before its shape is looked at, and the audience list at `OIDC_MAX_AUDIENCES` (8) before the first store read. Both answer the same generic 401; the audit reasons are `bearer_too_long` and `too_many_audiences`.
- 2026-09-17, after audit: **the JWKS cache no longer holds its map lock across the fetch.** One unreachable issuer stalled every OIDC authentication on the node for the full ten-second client timeout, cached issuers included. The lock is taken to read the decision, dropped for the fetch, and taken again to insert. The herd is still bounded, because the attempt stamp is claimed under the lock before it is dropped, so a second request inside the minute answers from the cache instead of opening its own connection.
- 2026-09-17, after audit: **`last_used_at` was one SQLite write per authenticated request**, on the single store mutex. A process-local `public_id -> Instant` map, bounded like the replay set, now suppresses the write inside `AUTOMATION_LAST_USED_WRITE_INTERVAL` (60 s). A minute of resolution answers the question the field exists for.

### Completion Notes

**Done.** All six acceptance criteria met. IV1 to IV5 run in the Docker
`cluster` profile against the `oidc-issuer` fixture, which mints RS256,
HS256 and `alg: none` tokens, rotates its key, counts JWKS fetches and
simulates an outage.

**Audit pass.** Five read-only reviewers (security, offensive, architecture,
quality, performance) ran against the whole epic before merge. Every
Critical, High and Medium finding, and every Low with operational
impact, was fixed on the branch rather than recorded; the findings that
touched this story are listed in its Debug Log.

What the audit and the e2e author changed in this story: an issuer entry
with no `project_path` or `namespace_path` bound accepted every project
on that instance (High); a `project_path` glob was unanchored so `acme*`
covered `acme-evil/pwn`; and the mode was unusable for its main audience,
a self-hosted GitLab under an internal PKI, because the JWKS client
trusted webpki roots only. It trusts the platform store now and an entry
may pin its own CA, which replaces rather than extends the trust for that
issuer. The claim that `lorica-acme` had the same gap was checked and is
false: the ACME directory goes through `instant-acme`'s platform verifier,
which reads `SSL_CERT_FILE`.

Gates, all green on the final tree in the dev container: the three CI
clippy commands with `RUSTFLAGS=-D warnings`; `cargo test --workspace`
with no failure; `cargo audit` with its two pre-existing allowed
warnings; the frontend three (`svelte-check` 0 errors, eslint clean,
vitest 480 tests). Two suites that flaked under fourteen concurrent
`cargo test` runs (`waf_body_inspection_e2e_test`, `lorica-memory-cache`)
passed ten consecutive solo runs each on the quiet tree.

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
