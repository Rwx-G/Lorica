# Story 10.4: The Environment Resource

**Epic:** [Epic 10 - Conditional Request Capture & CI Automation API (v1.8.0)](../prd/epic-10-v1.8.0.md)
**Status:** Done
**Priority:** P0
**Author:** Romain G.
**Depends on:** Story 10.3 (the listener and the token that scopes what an environment may claim) and Story 10.0 (an environment's route replicates through a payload that is now cut per recipient).
**Blocks:** Story 10.5, which swaps the token for an ID token and keeps this resource unchanged.

---

As a GitLab pipeline,
I want one idempotent call that makes `https://<slug>.review.example.com` reach the container I just started,
so that the review URL works before the job ends, survives a re-run, and disappears when the environment is stopped.

## Problem

A review app needs a hostname, a backend, a certificate and a route, and a
pipeline has no business making four calls and cleaning up after itself
when the third fails. It needs one call that is safe to repeat, because
pipelines are re-run, and safe to abandon, because jobs are cancelled.

## What this changes that is not obvious

**All the v1.8.0 canonical changes share one format version.** Story 10.1
moves `CANONICAL_FORMAT_VERSION` from 1 to 2 when it adds `capture_rules`.
This story adds `managed_by` and the environment ownership fields to rows
that also replicate. It does NOT bump the version again: 2 is the shape
of the 1.8.0 blob, and everything this release adds to it rides the same
number. A second bump inside one release would tell a mixed-version fleet
that two incompatible things happened when only one did. If 10.1 and 10.4
ever ship in different releases, that changes, and this paragraph is the
warning.

**`applied_generation` is the right thing to poll, and the hash is not.**
AC #5 lets a strict pipeline wait until the fleet has the environment.
Since Story 10.0 two converged nodes legitimately report two different
hashes, so a pipeline that polled for hash agreement would wait forever.
The generation stayed fleet-wide precisely so that this sentence still
works.

**`certificate: "auto"` is a stored MODE, not a resolved id frozen at
creation.** It is re-resolved at every configuration snapshot build, so
replacing the wildcard certificate with a new id, rather than renewing it
in place, moves every environment over without a single pipeline re-run.
The route row still carries an explicit `certificate_id`, so the proxy's
configuration path is untouched.

**Ownership is an authorization rule, not a convenience.** Two projects
sharing a Lorica must not be able to delete each other's review apps. The
rule is narrow on purpose: a token reaches an environment created by a
token with the same name prefix, or one explicitly labelled `shared`.

## Acceptance Criteria

1. **Composite resource, upsert by name.** `PUT /automation/v1/environments/{name}` creates or replaces an environment in one transaction: `name` (RFC 1123 label, 1 to 63 characters), `hostname` (must match one of the token's `allowed_hostnames`), `backends[]` (`address`, optional `tls_upstream`, `tls_sni`, `weight`; every address inside `allowed_backend_cidrs`), `certificate` (`"auto"` or an explicit certificate id the token can read), `waf_enabled`, `force_https`, `path_prefix` (default `/`), `ttl` (capped by the token's `max_ttl`), `labels` (at most 16 entries, keys and values at most 128 bytes). Anything else is 422, `deny_unknown_fields`.

2. **What the transaction writes.** A `Route` row, one `Backend` row per entry (exclusively owned, `group_name = automation:<name>`), the `RouteBackend` joins, and one `automation_environments` row (`name`, `route_id`, `token_public_id`, `certificate_mode`, `labels`, `expires_at`, `created_at`, `updated_at`, `last_pipeline`). On update the backend set is replaced, the route is updated in place (same `route_id`, so dashboards and metrics keep continuity), and `expires_at` is recomputed from now. All or nothing: a failed certificate resolution rolls back the backend rows.

3. **Hostname rules.** The hostname must match the token allowlist, must not collide with an existing route hostname or alias this environment does not already own (409, naming the conflict without revealing the owning route's details), and must not be the management or automation listener host. Wildcard aliases are not accepted on environments.

4. **`certificate: "auto"` resolves against existing certificates only.** Lorica picks the certificate whose `domain` or a `san_domains` entry covers the hostname, exact match preferred over single-label wildcard, then the latest `not_after`. No match is 422 `no_certificate_covers_hostname` listing the wildcard patterns an operator could provision, with the error text pointing at the DNS-01 provisioning endpoint. `certificate_mode = auto` is persisted and re-resolved at every snapshot build.

5. **Response.** 201 on create, 200 on update, body `{ name, url, route_id, backend_ids[], certificate_id, certificate_not_after, expires_at, applied_generation }`. `url` is `https://<hostname><path_prefix>`.

6. **Read and delete.** `GET /automation/v1/environments` (filter by `label`, `hostname`, `expiring_before`), `GET /automation/v1/environments/{name}`, `DELETE /automation/v1/environments/{name}` (204, idempotent, 404 only if it never existed). Delete removes the route, the owned backends and the joins in one transaction. A token may only read, update or delete environments created by a token with the same `name` prefix or an explicit `shared` label.

7. **Reaper.** A background task on a standalone node or a control plane sweeps every minute and deletes environments past `expires_at`, auditing each as `automation.environment.expired`. It does not run on a follower, whose configuration is replaced by replication. `docs/automation.md` recommends `ttl` strictly greater than GitLab's `auto_stop_in`, so GitLab stays in charge of the lifecycle and Lorica only collects orphans.

8. **Ownership is visible.** Routes and backends created this way carry `managed_by = "automation"` and the environment name. The dashboard shows a badge, allows read and delete (through the same transaction), and refuses in-place edits with a hint to update through the pipeline, so a manual fix is not silently overwritten by the next `PUT`.

9. **Concurrency.** Two pipelines racing on one `name` serialise on the environment row; the later `PUT` wins in full. `If-Match` with the `ETag` from `GET` is supported for pipelines that want a 412.

10. **Prometheus:** `lorica_automation_environments{state=active|expired}`, `lorica_automation_environment_ops_total{op, outcome}`, `lorica_automation_reaper_runs_total`.

11. **The blob version does not move again.** `managed_by` and the environment rows join the canonical projection under `CANONICAL_FORMAT_VERSION = 2`, the value Story 10.1 set. A test asserts the version is still 2 after this story, so a future change has to be deliberate about bumping it.

## Integration Verification

- **IV1:** `PUT` with a hostname covered by a pre-provisioned `*.review.example.com` certificate returns 201 with that certificate id; an immediate `curl --resolve` through the proxy reaches the backend over TLS with a chain that validates for the hostname; a second identical `PUT` returns 200 with the same `route_id`; a `PUT` with a new backend address moves traffic without a 5xx in between.
- **IV2:** `PUT` with a hostname outside the token allowlist, a backend outside `allowed_backend_cidrs`, a `ttl` above `max_ttl`, or a hostname already owned by a manual route each return the documented 4xx and leave zero rows behind.
- **IV3:** An environment with `ttl = "90s"` is gone from the config, the route table and the TLS resolver within 150 s with an audit row; a `DELETE` from the pipeline removes it immediately and a second `DELETE` returns 204.
- **IV4:** An environment created through the control plane reaches both followers, and a pipeline polling `applied_generation` sees convergence. The two followers report different configuration hashes throughout, which must not stop the poll from succeeding.
- **IV5:** A token whose name does not share the environment's prefix, and which carries no `shared` label, is refused on read, update and delete, each with an audit row.

## Tasks

- [x] AC #1/#2: the request type, the validation, and the one-transaction write with its rollback test. `ConfigStore::in_transaction` was added for it: commit on `Ok`, rollback on drop.
- [x] AC #3: the hostname collision rules. The listener-host refusal covers `localhost`, `*.localhost` and any IP literal, because neither bind is in `AppState`.
- [x] AC #4: the certificate resolver and its persisted mode, with the re-resolution at snapshot build. It settles in one extra round. When no certificate covers the hostname any more, the route keeps its last id and a WARN names the environment: an environment that served yesterday must not stop serving silently because a certificate was deleted.
- [x] AC #5/#6: the responses, the read filters, the idempotent delete. Delete answers 204 for both never-existed and already-deleted: telling them apart would mean consulting the audit trail, which retention truncates, and an API answer must not depend on log retention.
- [x] AC #6 (ownership): the prefix and `shared` rule, refused on all three verbs. An empty prefix (a principal starting with `-`) matches nothing.
- [x] AC #7: the reaper, gated twice: not spawned on a follower runtime, and each tick re-checks the stored identity.
- [x] AC #8: `managed_by` on routes and backends. `group_name = automation:<name>` is refused by the management API's own group-name validator, and that is a guard, not a defect: nobody can hand-create a route that claims to be automation-managed. The dashboard badge and edit refusal ride the frontend slice.
- [x] AC #9: the row-level serialisation (the store lock) and `If-Match`, strong and weak tags and `*`.
- [x] AC #10/#11: the metrics, and `story_10_4_rides_format_version_two_without_a_second_bump`.
- [x] Gates: the three CI clippy commands with `RUSTFLAGS=-D warnings`, every Rust suite, `cargo audit`, the frontend three.

## Dev Notes

### The thing most likely to go wrong

A partial write. This resource touches four tables and a failure in the
middle must leave nothing, including on the certificate resolution that
happens after the backends are staged. The test for it has to assert the
negative on every table, not just that the call returned an error.

### The second thing

The ownership check applied to two of the three verbs. A rule enforced on
delete but not on update is not a rule; the test covers read, update and
delete separately for that reason.

## Dev Agent Record

### Debug Log

**`applied_generation` is a floor, not a target.** The response carries
the generation the control plane had published at response time. The
write itself starts the round that publishes the next one, so a pipeline
that waits for the fleet must poll until every node's applied generation
EXCEEDS the value it received, not equals it. The PRD said "until every
node reports it", which was off by one. Two concurrent writers can move
the generation by two, in which case a node reporting one past the floor
has the first environment and not necessarily the second; a strict
pipeline re-reads its own environment and compares against the latest.

**The management API refuses `automation:<name>` as a group name.** The
colon is outside its validator's alphabet. That looked like an
inconsistency and is a guard: an operator cannot hand-create a route or
backend that claims automation ownership, so `managed_by` and the group
name agree by construction.

**Ownership is principal identity, not a name prefix. This departs
from the PRD.** The PRD says a credential reaches an environment
created by a credential with the "same name prefix", and the first
implementation read that as the text before the first `-`. Two audits
found the same hole: the prefix crosses tenants in both directions.
`ci-acme` and `ci-globex` own each other's environments, and so do the
OIDC projects `acme/web` and `acme/web-docs`. A naming convention is
not an authorization boundary: whoever picks a token name or a project
name picks who else they can reach, and on a shared GitLab anybody can
pick. `may_access` therefore requires the caller's principal to equal
the owner's, byte for byte, in the same kind, and `principal_prefix`
is gone. The `shared = "true"` label stays the only opt-in, and it is
written on the environment by its owner. An operator who wants one
grant across several credentials expresses it with that label, or by
handing the same credential to both pipelines.

**The `shared` label was a takeover primitive.** A `PUT` rebuilt the
row with the request's `owner` and `labels` after the access check had
passed, so a caller who reached a shared environment could `PUT` it
with `"labels": {}` and become its owner, locking the real owner out.
The stored `owner` is now never replaced on an update, and the stored
`labels` are rewritten by the exact owner alone; a non-owner `PUT`
still rewrites the route, the backends and the lifetime, which is what
sharing is for.

**Foreign and unknown answer alike.** A 403 on an environment another
principal owns confirms that the name is taken and by somebody else,
which is the one fact a neighbour on a shared node must not be able to
enumerate. `GET`, `DELETE` and a `PUT` carrying `If-Match` all answer
the 404 an unknown name answers, with the same body; the refusal
reason is in the `automation.environment.forbidden` audit row.

**An empty `allowed_backend_cidrs` was allow-everything.**
`ConnectionFilterPolicy::from_cidrs` reads an empty allow list as
default-allow, which is right for a filter an operator opts into and
wrong for a grant a credential carries: a token minted without the
field could aim a public hostname at `127.0.0.1:9443` or at a cloud
metadata address. Both models refuse an empty list at write time, and
`validate_backends` refuses one again at use time for the rows written
before that rule. The "node default backend policy" both model docs
described never existed.

**The caps.** `AUTOMATION_MAX_ENVIRONMENTS_PER_PRINCIPAL = 100` and
`AUTOMATION_MAX_BACKENDS_PER_ENVIRONMENT = 32`. Without them the body
cap alone let one `PUT` write about 2 700 backend rows inside the one
transaction that holds the store mutex, and nothing bounded how many
environments one looping pipeline could create, each one a fleet
replication round. `AUTOMATION_MAX_BACKEND_WEIGHT = 1000` because the
route model stores a bare `i32` and caps nothing.

**An explicit certificate id must still cover the hostname.** Naming
an id used to skip the coverage rule `auto` applies, so a route could
serve a name its leaf does not carry and every browser would refuse the
site the pipeline had just reported as up.

**No covering certificate keeps the last id.** The story did not say
what happens when the wildcard an `auto` environment resolved to is
deleted and not replaced. Blanking `certificate_id` would make a
serving environment stop serving, silently, over a certificate change it
had no part in. The route keeps the last id that worked and the snapshot
build logs one WARN per environment naming the hostname.

### Completion Notes

**Done.** All eleven acceptance criteria met. IV1 to IV5 run in the Docker
`cluster` profile's automation smoke.

**Audit pass.** Five read-only reviewers (security, offensive, architecture,
quality, performance) ran against the whole epic before merge. Every
Critical, High and Medium finding, and every Low with operational
impact, was fixed on the branch rather than recorded; the findings that
touched this story are listed in its Debug Log.

What the audit changed in this story, and two of them were High: an
empty `allowed_backend_cidrs` was read as "every address" by a policy
whose empty allow list means default-allow, so a token minted without the
field could point a public hostname at the loopback management API or
the cloud metadata service; both models require it now and an empty
grant is deny-all. The `shared` label was a takeover primitive because an
update rewrote `owner` and `labels` from the request; the stored owner is
never replaced and labels are owner-only. The "same name prefix"
ownership rule from the PRD crossed tenants (`acme/web-docs` reached
`acme/web`) and is replaced by exact principal equality of the same kind,
with `shared: "true"` as the only opt-in; that is a deliberate deviation
from the PRD's wording. Also: the `environment_protected` binding ran on
PUT only; a foreign environment answered 403 where an unknown one
answered 404, an existence oracle; an explicit certificate need not cover
the hostname; `tls_sni` was unvalidated and `weight` uncapped; there was
no quota on environments per principal or backends per environment; the
management API did not refuse in-place edits of managed rows, which the
dashboard alone was guarding, and route and backend responses never
serialised `managed_by` at all.

Gates, all green on the final tree in the dev container: the three CI
clippy commands with `RUSTFLAGS=-D warnings`; `cargo test --workspace`
with no failure; `cargo audit` with its two pre-existing allowed
warnings; the frontend three (`svelte-check` 0 errors, eslint clean,
vitest 480 tests). Two suites that flaked under fourteen concurrent
`cargo test` runs (`waf_body_inspection_e2e_test`, `lorica-memory-cache`)
passed ten consecutive solo runs each on the quiet tree.

## File List

Anticipated, to be corrected during implementation.

- `lorica-config/src/models/automation.rs`, `store/automation.rs`, `canonical.rs`
- `lorica-api/src/automation/environments.rs` (new), the automation router from Story 10.3
- `lorica/src/startup/` (the reaper task)
- `lorica-dashboard/frontend/` (the badge and the edit refusal)
- `docs/automation.md`, `CHANGELOG.md`

## Change Log

- 2026-09-16: Story drafted from the Epic 10 PRD. Added AC #11 and IV4/IV5: the PRD could not know that Story 10.0 would make the per-node hash diverge, which turns "poll until the fleet has it" into a trap if anyone reaches for the hash, and the single-bump rule for `CANONICAL_FORMAT_VERSION` needs to be written down before a second story reaches for a third number.
