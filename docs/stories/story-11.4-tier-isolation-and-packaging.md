# Story 11.4: Tier Isolation, Packaging and the Operator Story

**Epic:** [Epic 11 - Management MCP Server with Tiered Access (v1.9.0)](../prd/epic-11-v1.9.0.md)
**Status:** Done
**Priority:** P1
**Author:** Romain G.
**Depends on:** Stories 11.1, 11.2 and 11.3. The isolation check has to
know what a tier is, and the e2e profile drives all three.
**Blocks:** the release. AC #2 and AC #5 are what make the epic
installable and explicable rather than merely built.

---

As an operator setting this up for the first time,
I want the tiers to be obviously separate and the setup to be hard to
get subtly wrong,
so that I do not end up with one token that does everything because it
was easier.

## Problem

Every safety property this epic claims rests on one operational fact:
that the person deploying it made three tokens instead of one. Nothing
so far enforces that. A token carrying `logs:read` and `routes:write`
starts a server that reads attacker-authored text and holds a mutating
tool, which is precisely the session the tiering exists to prevent, and
today it would start without complaint.

## Acceptance Criteria

These are the PRD's, unchanged. They are the contract.

1. **One process, one tier, enforced at startup.** A token whose scopes
   span two tiers is refused with a message naming the offending
   scopes. The product refuses to build the convenient thing.
2. **Packaging.** `lorica-mcp` ships in the `.deb` and `.rpm` alongside
   the binary, and the three Dockerfiles carry the crate. It is not
   started by the systemd unit: it is launched by the operator's MCP
   client.
3. **Setup that shows its own blast radius.** `lorica mcp token create
   --tier read|config|admin` mints a Story 10.3 token with exactly that
   tier's scopes, prints it once, and prints what the tier can do next
   to it.
4. **The e2e Docker suite gains an `mcp` profile**: a real Lorica, a
   real automation listener, and a client driving each tier over stdio,
   asserting the tool lists, one mutation, the audit rows and one
   revocation.
5. Documentation: the full `docs/mcp.md`, the threat-model actor, and
   the hardening-guide guidance.

## Integration Verification

- IV1: A token carrying both `logs:read` and `routes:write` is refused
  at startup with both scopes named.
- IV2: The `mcp` e2e profile passes with all three tiers configured,
  and the audit chain verifies afterwards.

## Tasks

- [x] AC #1: the tier partition as data, and the startup refusal. The
      partition is derived from one table, not restated per tier, or it
      will drift the first time a scope moves between tiers.
- [x] AC #3: `lorica mcp token create --tier`, minting through the
      existing Story 10.3 path rather than a second minting route. The
      printed blast radius is derived from the tier's scope set, never
      transcribed beside it.
- [x] AC #2: packaging. `dist/build-deb.sh`, `dist/rpm/lorica.spec`,
      the four Dockerfiles (not three: `ci-check.Dockerfile` is the one
      the written rule omits), and the systemd unit left deliberately
      untouched with a comment saying why.
- [x] AC #4: the `mcp` e2e profile.
- [x] AC #5: `docs/mcp.md` complete, the MCP actor and the indirect
      injection path in `docs/security/threat-model.md`, the tier
      guidance in `docs/security/hardening-guide.md`.
- [x] IV1 and IV2.
- [x] Fix pass 2026-09-30 (the five audits of Story 11.4 and the
      maintainer's decisions 1 to 3 of the day): lifetimes by tier and a
      node-side `settings:write` ceiling, grant-filtered config-tier
      listings, query values withheld on the automation log read,
      `proxy_headers` values withheld from every automation answer, the
      `lorica` crate's flaky test fixed, and every other Medium and Low
      outside packaging and CI. See the Dev Agent Record.

## Dev Notes

### The CLI question, settled 2026-09-23

AC #3 specifies `lorica mcp token create --tier read|config|admin`,
while `docs/automation.md` documents `lorica automation token create
--scope ...` for the same Story 10.3 tokens. Nothing said whether the
first was a wrapper over the second or a second command, and two ways
to mint one credential is how an operator ends up holding a token
nobody can explain.

**Decided: a thin front end.** `lorica mcp token create --tier`
resolves a tier to its scope set and calls the existing minting path.
One creation route, one audit shape, one place where a token is born.
Its help text says so, so an operator reading it knows the two
commands are not alternatives with different properties.

Two consequences for the implementation. The tier-to-scopes resolution
is the same table AC #1's startup check reads, not a second copy beside
it. And the blast radius AC #3 prints is derived from that table at
print time, so a scope moved between tiers moves the printed sentence
with it rather than leaving it to be noticed.

### Packaging a binary the unit does not start

AC #2 ships `lorica-mcp` in the packages and AC #2 also says the
systemd unit must not start it. Both halves matter. An MCP server is
launched by the client that talks to it, and a long-running system
service holding an automation token would be exactly the ambient
credential this design refuses. The unit file should carry a comment
saying that the omission is deliberate, because the next person to
read it will assume it is an oversight.

### Where the isolation check cannot help

AC #1 refuses a token spanning two tiers at startup. It cannot refuse
an operator who mints three tokens and gives all three to one client,
nor one who runs the admin tier permanently because it was convenient
once. AC #4 of Story 11.3 asks the hardening guide to recommend
removing the admin tier after the task that needed it; this story is
where that guidance actually lands.

### What the existing e2e suite does and does not cover, measured

On 2026-09-23, after lots 2a to 4 of Story 11.1 landed, the Docker
suite (base, cluster, restart, automation and revocation phases) passed
at 553 assertions and zero failures, the same 553 it passed before any
of those lots existed. That is evidence of two things at once. Nothing
already covered broke: the whoami scope change, the nine read paths,
the MCP endpoint and the new audit row shape coexist with every
existing assertion. And none of the new surface is covered: the count
did not move because the automation smoke never calls a read path or
the MCP endpoint. AC #4 is therefore the first end-to-end exercise of
the whole read tier, not a regression net over one that exists.

### There is no tier table yet, and two things already want one

Recorded 2026-09-23 from the architecture audit of Story 11.2. The
config tier's startup notice tells a token that carries write scopes
and no read scope to add `logs:read`, because the tier's tools need
the reads. Nothing defines what a config-tier token is allowed to
carry, so that advice and this story's AC #1 refusal are written
against no shared definition and can contradict each other the day
either moves.

AC #1's partition is therefore not only the startup check's input, it
is what the startup notice, the `--tier` minting command, the printed
blast radius and the tier filter in `McpServer` all read. One table,
in `lorica-mcp`, naming for each tier the scopes it requires and the
scopes it tolerates (the config tier tolerates the read scopes its
tools need; the read tier tolerates none of the write scopes), with a
test that every `AutomationScope` variant appears in exactly one
tier's required set. A token is refused at startup when its scopes
span two tiers' required sets, and the notice for a token missing a
tolerated read scope names the tier's own definition rather than a
sentence written beside it.

## Dev Agent Record

### Debug Log

- 2026-09-30, lot A: the README product-crate test count was
  recomputed from the product-crate run (2914 to 2947), both places, and
  the Vitest figure from the frontend run (480 to 506, a figure that had
  drifted before this lot too).
- The Bash tool's heredocs rewrote `\` line continuations inside
  Python edit scripts, which is how two string literals lost theirs on
  the first pass; every edit script after that was written with the
  Write tool and run as a file, and the runs of spaces are asserted
  absent by tests on both credential models.

### Completion Notes

Lot A (AC #1, AC #3, the grants decision, the docs for those), done
2026-09-30 by Romain G.

**The tier table.** `TIERS` in `lorica-mcp/src/tier.rs`, one row per
`Tier` (`Read`, `Config`, `Admin`, in increasing order of reach), each
naming the scopes the tier requires and the scopes of another tier it
tolerates. The read tier requires every read scope and tolerates
nothing; the config tier requires the write scopes a grant bounds and
tolerates the read scopes of the rows its previews answer; the admin
tier requires `settings:write` and tolerates nothing. The constant is
the authority and is not restated here. Tests hold it: every
`AutomationScope` variant is required by exactly one tier (walked from
`AutomationScope::ALL`); a tier's tolerated set equals the read scopes
its own tools' summaries and id parameters send the caller to, minus
what it requires (derived from the catalogue text, so a config tool that
starts naming another listing turns it red); the read tier requires and
tolerates no write; every pair of scopes from two tiers is refused
unless the higher tier tolerates the lower one's scope, walked over the
whole table; and the grant-bounded scopes are exactly the config tier's
required set.

`resolve` takes the highest-reaching tier whose required set the token
touches, and refuses any scope that tier does not allow, naming the
anchoring scopes and the offending ones with the tier each belongs to.
A scope no tier knows and an empty scope set are refused too.

`ToolSpec` carries `tier: Tier`. For a mutation's pair the catalogue sets
it from the array (`MUTATIONS` gives `Config`, `ADMIN_MUTATIONS`
`Admin`); the nine `READS` literals carry `tier: Tier::Read` beside the
`kind: Kind::Read` they already carried, since they are literals and
not built. A test pins the nine `READS` literals against their
array; for a mutation the catalogue sets the tier from the array, so
that half of the test cannot fail and says so (fix pass). The string
`tier()`, `is_admin_tool` and the `read_scopes`/`write_scopes`/
`admin_scopes` helpers are gone; the startup notice, the registration
filter (`Tier::serves`: the tier's own tools and the reads it
tolerates, then filtered by what the token holds), `why_not`, the
`--tier` command and the blast radius all read the table. (Fix pass:
the registration filter and the blast radius now share one predicate,
`Tier::registers`.)

**The refusal, both bindings.** `McpServer::sharing` and `over` return
`Result<McpServer, TierError>`; `introspect` maps it to
`StartupError::Tier`, which the stdio `main` exits on with 78
(`EXIT_MISCONFIGURED`: the plane answered, the token is the wrong one).
The Streamable HTTP handler answers **403** with a JSON-RPC error
(`-32600`) under the request's id, naming the scopes, and attaches an
`McpCallRecord` with the new `Outcome::SpansTiers`, so the row reads
`automation.request.forbidden:spans_tiers` (published in
`AUTOMATION_AUDIT_REASONS` and in `docs/automation.md`). 403 because it
is what this listener answers every refusal of a live credential that
may not do what it asked (the scope gate's missing grant, the endpoint's
own `Origin` refusal); not 401, the credential is live; not a 200
execution error, since no server was built. IV1 is a test on each
binding: `iv1_a_token_spanning_two_tiers_never_becomes_a_server_on_either_constructor`
(`lorica-mcp`, through `introspect`, the stdio path) and
`iv1_on_this_binding_a_token_spanning_two_tiers_is_refused_with_both_scopes_named`
(`lorica-api`, through the whole Streamable HTTP stack, audit row
included).

**Grants, typed absence.** `AutomationScope::is_grant_bounded`, an
exhaustive match, is the one place the set is decided:
`environments:write`, `routes:write`, `backends:write`,
`certificates:write`. Verified on the code: `put_environment` checks
the hostname and every backend address; the route, backend and
certificate write handlers run `ensure_hostnames_granted`,
`ensure_backend_address_granted` and the three guards; no read handler
and not `update_settings` reads either grant. `validate_automation_grants`
(in `lorica-config`, exported) requires both grants non-empty when a
bounded scope is carried and refuses both when none is; the static
token and the OIDC issuer entry call it, and so do both CLI commands
before they log in. Every consumer was audited for an empty list:
`allows_hostname` (token, issuer entry, principal) is an `any` over the
patterns and matches nothing; `ensure_backend_address_granted` refuses an
empty CIDR list before it builds the connection filter, and the backend
row guard goes through it. Regression tests: an empty CIDR list admits
no address (including loopback, the metadata address and a v4-mapped v6
loopback) and an empty hostname list admits no host, on the claim checks
and on the stored-row guard (`write.rs`), and on both models'
`allows_hostname`.

**Migration of stored tokens: accept on load.** The rule is a mint and
registration rule; the store never re-validates a row it loads. A read
token minted before this release keeps the grants the old rule forced
on it and keeps working, since no path it reaches reads them. The
dashboard renders the grants of any token without a bounded scope as
"not applicable", whatever the row stores. A store test pins that such a
row still loads. The least surprising choice: nothing an operator has
deployed stops working, and nothing in the UI claims a blast radius the
node does not apply.

The mint API and the issuer registration accept the two fields
omitted (`#[serde(default)]`, `required` updated in `openapi.yaml`);
`lorica automation token create` no longer requires `--hostname` and
`--backend-cidr` at parse time. The dashboard's mint form shows the two
grant fields only while a bounded scope is ticked and sends them only
then; the bounded set reaches TypeScript as `GRANT_BOUNDED_SCOPES` in
`automation-scopes.generated.ts`, which
`lorica-api/tests/automation_scope_fixture.rs` diffs against
`is_grant_bounded` both ways, as it already did the scope list.

The missing line continuation in the backend CIDR message was also in
the OIDC issuer entry's copy and in its "must bind one of" message; all
three are fixed, the first two by the shared function.

**OIDC issuer entries (orchestrator decision, 2026-09-30).** An issuer
entry keeps the config tier's write scopes allowed: a keyless,
short-lived CI credential is what OIDC is for, and it is safer than a
static token. Only `settings:write` stays refused, as since Story 11.3.
The threat model records this in lot D. The issuer test that walks every
scope says so beside the loop.

**`lorica mcp token create --tier`.** `lorica/src/cli_mcp.rs`, a front
end: the scopes are `Tier::minted_scopes()`, the body is
`cli_automation::mint_request_body`, the request is
`cli_automation::mint`, the one function `automation token create`
now mints through too. Token alone on stdout, notice and blast radius
on stderr. The config tier mints its tools' write scopes AND the three
reads it tolerates: every config preview answers the row it would
change and needs that row's read scope (`ensure_preview_readable`), and
the tools find their ids through the read listings, so without them a
config token registers previews that are refused. The environment
scopes sit in the table but are never minted, since no MCP tool uses
them. `--hostname`/`--backend-cidr` are required for config and refused
for read and admin, decided by `is_grant_bounded` over the minted
scopes, then the model's shape rule. The blast radius is computed at
print time from the table, the catalogue and, for the admin tier,
`lorica_api::automation::write::SETTINGS_ALLOWLIST` (reachable from the
binary crate), with each setting's bound, reach and takes-effect.

Decided on my own, for the orchestrator to confirm:

- The flag is `--backend-cidr`, not `--cidr`: it is the spelling of the
  command this one fronts, and two spellings of one grant across two
  commands that are meant to be the same route would be a second thing
  to remember.
- `--name` is optional and defaults to `mcp-<tier>`; AC #3's command
  line names no label. `--max-ttl-seconds` is not offered: it bounds
  environments, which no MCP tool creates.
- `lorica` gains a path dependency on `lorica-mcp` (a workspace crate,
  no new external dependency) so the command reads the table rather than
  a copy. Both bump checklists now list `lorica-mcp` among the pins of
  `lorica` and of `lorica-api` (the latter pin predates this lot and was
  missing from both). The skill's copy,
  `.claude/skills/bump-version/bump-checklist.md`, is git-ignored
  (`.claude/.gitignore`), so the edit is local to this clone and appears
  in no diff (fix pass).
- The tolerated reads register their read tools on a config server, as
  before; a tool of another tier whose scope the server's tier does not
  tolerate is answered "belongs to the X tier ... one process serves one
  tier" rather than "needs the scope", which it could never gain here.
- `WriteFixture` in `lorica-api/src/tests.rs` mints a second, config-tier
  token under the same name for the MCP endpoint (`mcp_bearer`); the
  every-scope token stays for the automation plane's own paths, which
  the tier rule does not concern. The whole-catalogue sweep now drives
  one token per tier.

Lot B (AC #2, packaging), done 2026-09-30 by Romain G.

- `dist/build-deb.sh` and `dist/build-rpm.sh` take the MCP binary as an
  optional second argument, next to `lorica` by default;
  `dist/rpm/lorica.spec` installs it and lists it in `%files`. Both
  package descriptions name it.
- CI builds `-p lorica -p lorica-mcp`, checks that an unconfigured
  `lorica-mcp` exits 78, uploads it with the release binary, and fails
  the deb and rpm install jobs if the binary is missing or if the unit
  starts it.
- All four Dockerfiles carry the crate. The production image also ships
  the binary, so a client can launch a version-matched server with
  `docker exec -i`; the e2e image builds it for the `mcp` profile.
- `dist/lorica.service` is unchanged but for a comment saying the
  omission is deliberate.
- Verified in `rust:1-bookworm` from HEAD sources (lot A was mid-edit):
  `dpkg -c` and `rpm -qpl` both list `/usr/bin/lorica-mcp` at 755. To
  re-verify on the final tree.

Lot D (AC #5, the documentation), done 2026-09-30 by Romain G.

**`docs/mcp.md`, the operator reference.** Restructured for an operator
setting it up the first time: what it is not, the tiers and the
one-process-one-tier refusal on each binding (stdio exit 78 with the
message, Streamable HTTP 403 `-32600` and `spans_tiers`), a five-step
setup, one minting section (the three that overlapped merged) with
grants as typed absence and an example per tier, the tiers, running it
(the packages and why no unit starts it, the container with
`docker exec -i` and `-e LORICA_MCP_TOKEN` passed by name, the stdio
and Streamable HTTP client configuration, including the self-signed
leaf's location, names and rotation), paging, rate limits and write
budgets, audit, revocation and expiry, troubleshooting by exit code
and status, and the protocol revision. The read and config tool tables
were transcriptions of `READS` and `MUTATIONS` that no test pinned;
they are now a description of each tool family pointing at the
constants and at the blast radius `--tier` prints. The admin settings
table, pinned by `lorica-api/tests/admin_tier.rs`, is unchanged. One
fact documented for the first time, checked in `router.rs`: a preview
spends from the same per-credential write budget as its apply.

**Threat model.** Trust boundary 9 and T9: the actor (a model steered
by attacker-written text, indirect prompt injection), what it reaches
per tier, each control with its status, the residuals accepted as
documented (preview is not a control; the config tier accepts
`error_page_html`, rewrites and redirects inside its grant; protocol
drift), what the isolation check cannot help with, the OIDC decision
of 2026-09-30, and query-string secrets reaching the model recorded as
open and undecided. Residual risks 5 to 7 added.

**Hardening guide.** "The MCP Admin Tier" became "The MCP Server
Tiers", with the Story 11.3 paragraph kept inside it rather than
repeated: which tier for which task, one token per tier with `--tier`,
one client per tier, never a config token for a read client, the admin
tier only for the task, an explicit short `--lifetime-days`, narrow
grants, stdio over a hosted client, and which audit rows to alert on.
The prose list of settings is now a pointer to the pinned table.

**`docs/automation.md`, for consistency.** The source allowlist
reloads on the next accepted connection (the document said it was
fixed when the listener opens, which `listener.rs` contradicts); the
MCP endpoint paragraph names three tiers and the `spans_tiers`
refusal; `settings:write` added to the 403 reason table.

Lot C (AC #4, IV1 end to end, IV2), done 2026-09-30 by Romain G.

The `mcp` profile of the Docker e2e suite:
`tests-e2e-docker/entrypoint-mcp.sh` boots a standalone node whose
automation listener is bound on loopback (allowlist `127.0.0.1/32`,
seeded over two boots as the control plane's entrypoint does), and
`tests-e2e-docker/test-runner/run-mcp-smoke.sh` drives it. The smoke
runs from the Lorica image rather than the alpine runner, which cannot
execute the glibc `lorica` and `lorica-mcp` binaries, and shares the
node's network namespace because `lorica mcp token create` mints
through 127.0.0.1 only; with no jq in that image, JSON is read with the
sqlite3 CLI's JSON functions. For each tier it mints with the real
`--tier` command, spawns `lorica-mcp` as a coprocess and speaks
newline-delimited JSON-RPC to it, with the revision read off the
binary's own banner and sent in `_meta` on every request. The expected
tool list is parsed from the command's printed blast radius, so the
printed blast radius and the served list are checked against each other
end to end rather than against a list in the script. (Corrected in the
fix pass: this does not exercise the server's tier filter, which removes
nothing for a token the tier check accepts; see `Tier::registers`.) It asserts one mutation
and one plane refusal per mutating tier (a route inside and outside the
hostname grant; `access_log_retention` raised, then lowered), a tool of
another tier as a protocol error that leaves no row, and each call's
audit row with the established principal and request line and the
transport and tool inside `asserted[...]`. It also covers a mid-session
revocation (execution error carrying the 401, a `token_revoked` row, a
fresh start exiting 69), IV1 through `lorica automation token create`
(exit 78, both scopes named), and IV2 (`/api/v1/audit/verify`
verified). 51 assertions; `./run.sh --build` passes every phase, with a
`--skip-mcp` opt-out. (Fix pass: 53 assertions, the
no-row check now on all three tiers and taken after the drain.)

### Fix pass, 2026-09-30

Done by Romain G. on the five audit reports of the day (security,
pentest, quality, debt, architecture), each finding re-verified on the
code first. Packaging, CI and the four Dockerfiles were a parallel
pass and are not recorded here.

**Decision 1, lifetimes.** `TierDefinition` carries
`default_lifetime_days` (read 90, config 7, admin 1), and
`lorica mcp token create --tier` always sends it when `--lifetime-days`
is omitted and prints it with the blast radius. The ceiling is
`AUTOMATION_SETTINGS_WRITE_MAX_LIFETIME_DAYS = 7` in `lorica-config`,
enforced in `AutomationToken::validate` for any token carrying
`settings:write`, so every mint surface is bounded; the refusal (422)
names the ceiling. Decided here: the constant lives in `lorica-config`,
the only crate every mint path shares, and the tier table cannot
disagree with it because `tier.rs` asserts every tier minting
`settings:write` defaults at or beneath it, and `cli_mcp.rs` validates
the token each tier would mint by default through the model itself. A
`settings:write` mint naming no lifetime is refused, not clamped: the
node's default is longer, and a silent shortening would hide the rule.

**Decision 2, config-tier reads filtered by grant.** For a principal
carrying a grant-bounded scope (`AutomationPrincipal::carries_grants`,
keyed on the scopes rather than on the lists, so a legacy read token
that still stores grants keeps reading everything), the automation
`/routes`, `/backends` and `/certificates` answer only rows inside its
grants, by the write guard's own predicates, now shared functions in
`write.rs` (`route_names_granted`, `certificate_names_granted`) and
`ensure_backend_address_granted`. Paging walks the filtered set. The
MCP tools reach the same handlers. Get-by-id: none of these resources
has a single-row read on the plane, so there is no row to answer as
not-found; writes and previews by id keep their 403 naming the id and
nothing else (ids are server-minted random values, so the 403/404
difference reveals nothing a caller could not already name, and a 404
would send an operator looking for a row that exists). SLA reads are
left unfiltered: they are numbers keyed by route id, behind a read-tier
scope. Tested with an operator row, another principal's planted row
(an `error_page_html` instruction) and an in-grant row, on the plain
plane and through MCP. T9 corrected.

**Decision 3, query-string values.** Checked on the row shape first:
the proxy logs `uri.path()`, so an access-log row has never carried a
query string, and the threat model's premise was false. The mask ships
anyway as the maintainer decided, on the automation log read only
(`redact::access_log_row`): every query value replaced by `[redacted]`,
names kept, a fragment replaced whole, nothing decoded (so `%26`/`%3D`
stay inside their value and malformed encoding cannot defeat it), bare
`?flag` kept as a name, repeated keys each masked, empty values masked.
The row carries no referer or user-agent field. WAF events carry no URI
or query, only the span a signature matched, and are left as recorded:
masking the span would erase the attack the event exists to show.
Decided here. The dashboard and sinks are unchanged. T9's open item is
closed as decided.

**Per finding.**

- Pentest High, `proxy_headers` values: fixed. `lorica-api/src/automation/redact.rs`
  withholds them (names kept), plus `forward_auth.address` userinfo and
  query values and backend `health_check_path` query values, the same
  class; applied to the read listings and every route and backend write
  answer and preview, `changes` included. Other credential-bearing
  fields checked: `basic_auth_password` never enters the view,
  `mtls.ca_cert_pem` is a public CA, `header_rules` values are writable
  by the tier itself, `response_headers` go to every visitor. Pinned by
  a test walking listing, apply, two previews and the MCP tool. T9
  "reads no Lorica secret" and "withhold them" made true.
- Flaky `rebuild_from_store_swaps_global_handle`: root cause is
  `cert_reload_commit_tests`, whose `handle_config_reload_commit` calls
  `apply_per_process_reload_state` and rebuilds the process-wide
  AI-crawler handle from a store without the test's row, between that
  test's rebuild and read. Fixed with a test-only
  `TEST_HANDLE_WRITERS` lock in `ai_bot_merged.rs` held by every writer
  in the binary; no retry, no sleep.
- Security Low, backend grant fail-open on unparsable stored CIDRs:
  fixed, every entry parsed, one bad entry refuses the grant whole.
- Security Low, CLI password to any loopback listener: not fixed.
  Pre-existing for every management CLI command; a correct fix must
  learn which certificate the node serves (the operator override lives
  in the settings) and decide what a caller without data-dir access
  gets. Recorded as `docs/backlog.md` #90 and a T9 row. Needs the
  maintainer's decision.
- Security Low, `> tier.token` at 0644: fixed, `umask 077` in every
  example. Info, e2e password copy: fixed the same way.
- Security Low and Pentest Medium, the container exec: documented.
  `docs/mcp.md` puts stdio from the client's host first and names both
  costs of `docker exec`; T9 and the hardening guide state that a
  client with Docker access and a shell tool is outside the tier model.
- Pentest Low, tolerated set pinned to prose: a structural test, a
  tier may tolerate `X:read` only when it requires `X:write`.
- Pentest Low and Debt High and Quality Medium, alerts that never fire
  over stdio: the hardening guide splits the alerts by binding; T9 and
  `docs/mcp.md` say "every call that reaches the node".
- Pentest Info, token thief: one T9 sentence.
- Quality Medium, CHANGELOG contradictions: fixed, and the container
  entry names the CA bundle (Debt Low).
- Quality Medium, scope parsing twice: `AutomationScope::as_str` and
  `from_wire`, pinned against serde by a test; one
  `cli_automation::grants_refusal` speaking the flags' words for both
  commands (Quality Low, grants rule restated, fixed too).
- Quality Medium, e2e seeding duplicated: not fixed. A sourced helper
  needs a `COPY` line in `tests-e2e-docker/Dockerfile`, outside this
  pass.
- Quality Medium, stale count in `lorica-mcp/Cargo.toml`: fixed.
- Quality Medium, smoke aborting on a dead server: `trap '' PIPE`, a
  liveness check after startup, `MCP_OUT` closed.
- Quality Low, `TierError`: the version-skew case now says so and
  points at the matching `lorica-mcp`, the verb agrees in number, and
  the remedy is appended per credential (static token: `--tier`; OIDC
  principal over Streamable HTTP: one issuer entry per tier), which also
  closes the architecture Low. Decided here: kept as a struct, since
  its fields are what both bindings and the tests read.
- Quality Low, errors: `StartupError::source` implemented; `thiserror`
  not adopted (a new dependency).
- Quality Low, the admin literal, two vocabularies, eight parameters,
  self-built tests: fixed (`spec.tier == Tier::Admin`,
  `Reach::describe`/`TakesEffect::describe` shared with the docs pin,
  `TierMint`/`TokenMint`, and `mint_tier`/`mint_token` asserted with a
  fake mint for the body and the stdout/stderr split).
- Quality Low, smoke `set -u` and parsed prose: commented; the
  `  Scopes:` line is pinned by a Rust test. Hard-coded ports left as
  they are.
- Quality Low, the docs refusal example: pinned by a test that renders
  the IV1 refusal.
- Quality Low and Debt Low, Lot B re-verification: the packaging pass's.
- Quality Low, the repeated subject literal: `AUTOMATION_TOKEN_SUBJECT`.
- Debt Medium, `why_not` untested: tests assert the tier message across
  tiers and the scope message within one.
- Debt Medium, `Tier::serves` inert: kept as a tripwire and said so
  (`Tier::registers` doc, smoke header, this record).
- Debt Low, `McpCallRecord` doc, `config.rs` message (now held to
  serde's own field list by a test), tautological array test comment,
  no-row check on one tier, stale comments (`tools.rs`, `stdio.rs`,
  the generated fixture's header), exit 74 row: fixed.
- Debt Low, the numbers in `docs/mcp.md`: pinned, with those in
  `docs/automation.md`, by `lorica-api/tests/operator_reference_figures.rs`.
- Debt Low, `.claude/rules/lorica-rust.md` wrong about
  `ci-check.Dockerfile` and missing `-p lorica-mcp`: not changed; agent
  rules are the maintainer's to edit.
- Architecture Medium, smoke startup race: waits for the startup
  notice, which follows the `whoami` round trip.
- Architecture Low, two registry predicates: `Tier::registers`, and a
  test compares the printed blast radius with `McpServer::over`'s
  registry for each tier.
- Architecture Low, T9 "the node refuses" over stdio: stated where each
  binding enforces.
- Architecture Low, OIDC refusal not tied to the tier table: `tier.rs`
  asserts an issuer entry refuses every admin-tier scope.
- Architecture Low, stale statements (`main.rs`, `server.rs`, `cli.rs`,
  `component-architecture.md`): fixed.
- Architecture Low, tolerated reads against the runtime: confirmed, the
  `lorica-api` catalogue sweep drives every config preview with exactly
  `Tier::Config.minted_scopes()` and asserts no execution error.
- Not done, by design or scope: the dashboard tier hint and the mint-time
  spanning-set warning (Info and "later"), jq in the e2e image
  (Dockerfile), CI list changes (the parallel pass).

**Tests.** The read-surface fixture token in `lorica-api/src/tests.rs`
now carries the scopes no grant bounds and no grants, since the field
walk needs node-wide rows; granted listings have their own tests. README
product-crate count 2947 to 2975.

**Audit follow-up: .deb ownership (pentest High 2) and the dark `lorica`
crate (quality and architecture CI High).** Every released .deb, 1.0.0
to 1.8.0, lists all entries as `runner/runner` (uid 1001) in
`dpkg-deb -c`; every .rpm is `root/root` apart from the data dir. dpkg
resolves the owner by name first, then by uid. `dist/build-deb.sh` now
uses `dpkg-deb --root-owner-group` with explicit modes, and its postinst
resets to `root:root` any path from `dpkg-query -L lorica` outside
`/var/lib/lorica` that has another owner. Verified in
debian:bookworm-slim by upgrading 1.8.0 to a fixed build packaged as a
uid-1001 user: dpkg's unpack fixes the replaced files but leaves
`/usr/share/doc/lorica` with uid 1001, the postinst fixes it, the data
dir stays `lorica:lorica 750`, and a reinstall changes nothing. CI now
asserts root ownership in the package listing and on the installed
binaries and unit (deb and rpm), runs `cargo test -p lorica --features
otel`, counts `-p lorica` in coverage, and lints `lorica-mcp`'s tests;
`ci-check.Dockerfile` mirrors that and no longer ignores the `lorica`
tests or `cargo fmt`. A GitHub Security Advisory draft for the .deb
ownership is kept outside the repository for the maintainer to publish.

## File List

- `lorica-mcp/src/tier.rs` (new)
- `lorica-mcp/src/lib.rs`, `lorica-mcp/src/main.rs`,
  `lorica-mcp/src/server.rs`, `lorica-mcp/src/stdio.rs`,
  `lorica-mcp/src/tools.rs`
- `lorica-config/src/models/automation_token.rs`,
  `lorica-config/src/models/oidc_issuer.rs`,
  `lorica-config/src/models/mod.rs`,
  `lorica-config/src/store/automation_token.rs`
- `lorica-api/src/automation/mcp.rs`,
  `lorica-api/src/automation/audit.rs`,
  `lorica-api/src/automation/write.rs`,
  `lorica-api/src/automation_tokens.rs`,
  `lorica-api/src/automation_tokens/tests.rs`,
  `lorica-api/src/oidc_issuers.rs`, `lorica-api/src/tests.rs`,
  `lorica-api/tests/admin_tier.rs`,
  `lorica-api/tests/automation_scope_fixture.rs`,
  `lorica-api/openapi.yaml`, `lorica-api/openapi-automation.yaml`
- `lorica/src/cli_mcp.rs` (new), `lorica/src/cli.rs`,
  `lorica/src/cli_automation.rs`, `lorica/src/main.rs`,
  `lorica/Cargo.toml`, `Cargo.lock`
- `lorica-dashboard/frontend/src/components/settings-tabs/AutomationTokensTab.svelte`,
  `AutomationTokensTab.test.ts`, `automation-scopes.generated.ts`,
  `lorica-dashboard/frontend/src/lib/api.ts`
- `docs/automation.md`, `docs/mcp.md` (tier isolation and `--tier`
  sections only), `CHANGELOG.md`, `README.md`, `docs/BUMP-CHECKLIST.md`,
  `.claude/skills/bump-version/bump-checklist.md`,
  `docs/architecture/source-tree.md`,
  `docs/architecture/component-architecture.md`
- Lot B: `dist/build-deb.sh`, `dist/build-rpm.sh`,
  `dist/rpm/lorica.spec`, `dist/lorica.service`, `Dockerfile`,
  `tests-e2e-docker/Dockerfile`, `ci-check.Dockerfile`,
  `.github/workflows/ci.yml`
- Lot C: `tests-e2e-docker/entrypoint-mcp.sh` (new),
  `tests-e2e-docker/test-runner/run-mcp-smoke.sh` (new),
  `tests-e2e-docker/docker-compose.yml`, `tests-e2e-docker/Dockerfile`,
  `tests-e2e-docker/run.sh`
- Lot D: `docs/mcp.md` (full), `docs/security/threat-model.md`,
  `docs/security/hardening-guide.md`, `docs/automation.md`
- Fix pass: `lorica-api/src/automation/redact.rs` (new),
  `lorica-api/tests/operator_reference_figures.rs` (new),
  `lorica-api/src/automation/{read,write,environments,auth,mcp,mod}.rs`,
  `lorica-api/src/automation_tokens/tests.rs`, `lorica-api/src/tests.rs`,
  `lorica-api/tests/admin_tier.rs`, `lorica-api/openapi.yaml`,
  `lorica-api/openapi-automation.yaml`,
  `lorica-config/src/models/{automation_token,mod}.rs`,
  `lorica-mcp/src/{tier,server,config,main,tools,stdio}.rs`,
  `lorica-mcp/Cargo.toml`, `lorica/src/{cli_mcp,cli_automation,cli,main}.rs`,
  `lorica/src/proxy_wiring/{ai_bot_merged,ai_bot_reload_tests,cert_reload_commit_tests}.rs`,
  `lorica-dashboard/frontend/src/components/settings-tabs/automation-scopes.generated.ts`
  (comment), `tests-e2e-docker/entrypoint-mcp.sh`,
  `tests-e2e-docker/test-runner/run-mcp-smoke.sh`, `docs/mcp.md`,
  `docs/automation.md`, `docs/security/threat-model.md`,
  `docs/security/hardening-guide.md`, `docs/backlog.md`,
  `docs/architecture/source-tree.md`,
  `docs/architecture/component-architecture.md`, `CHANGELOG.md`,
  `README.md`. The skill copy of the bump checklist listed under Lot A is
  git-ignored and local to the clone.
- Backlog #90: `lorica/src/cli_client.rs` (new),
  `lorica-api/src/management_tls.rs`, `lorica-api/src/server.rs`,
  `docs/security.md`, `tests-e2e-docker/docker-compose.yml`.
- Pre-merge audit fixes, automation plane (2026-09-30):
  `lorica-api/src/automation/{write,read,audit,auth,environments,mcp,router,scope}.rs`,
  `lorica-api/src/automation/environments/tests.rs`,
  `lorica-api/src/automation/oidc/{mod,replay,jwks,tests,test_support}.rs`,
  `lorica-api/src/{target,db,audit,log_store,logs,sla,backends,settings,management_tls,tests}.rs`,
  `lorica-api/src/routes/crud.rs`, `lorica-api/src/acme/renewal.rs`,
  `lorica-api/tests/{openapi_contract,mcp_asserted_headers,automation_scope_fixture}.rs`,
  `lorica-api/openapi-automation.yaml`,
  `lorica-config/src/models/automation_token.rs`, `lorica-mcp/src/tools.rs`,
  `docs/mcp.md`, `docs/automation.md`, `docs/security.md`,
  `docs/security/threat-model.md`, `docs/security/hardening-guide.md`,
  `docs/installation.md`, `docs/hot-upgrade.md`, `docs/backlog.md`,
  `docs/architecture/{source-tree,component-architecture,api-design-and-integration}.md`,
  `CHANGELOG.md`, `README.md`.

## Change Log

- 2026-09-23: Drafted from the Epic 11 PRD, carrying the unreconciled
  CLI question the Epic 11 context compilation surfaced.
- 2026-09-23: The CLI question settled as a thin front end over the
  existing minting path, with the tier-to-scopes table shared with AC
  #1's startup check and the printed blast radius derived from it.
- 2026-09-30: Lot A. AC #1: the tier table and a typed `Tier` on every
  tool, the refusal in the constructor both bindings share (stdio exit
  78, Streamable HTTP 403 `spans_tiers`), IV1 tested on both. Grants as
  typed absence (maintainer decision of the day), with the grant-bounded
  set decided by `AutomationScope::is_grant_bounded`, accept-on-load for
  stored rows, the dashboard's "not applicable", and the CIDR message
  bug fixed. AC #3: `lorica mcp token create --tier` over the existing
  mint route, with a blast radius derived at print time. Status to
  InProgress.
- 2026-09-30: Lot B. AC #2: `lorica-mcp` in the `.deb`, the `.rpm`, the
  production image and the release binaries; CI checks the binary is
  shipped and that the unit does not start it.
- 2026-09-30: Lot D. AC #5: `docs/mcp.md` completed for a first setup,
  the MCP actor and T9 in the threat model with query-string secrets
  recorded as open, the tier guidance in the hardening guide, and three
  stale statements in `docs/automation.md` corrected.
- 2026-09-30: Lot C. AC #4: the `mcp` e2e profile, 51 assertions, every
  tier driven over stdio with the real `--tier` minting command; IV1
  and IV2 end to end. Full suite green.
- 2026-09-30: Fix pass on the five audits and decisions 1 to 3: tier
  lifetimes and the `settings:write` ceiling, grant-filtered listings,
  query values withheld on the automation log read, `proxy_headers`
  values withheld from every automation answer, the `lorica` crate's
  flaky test, and the Medium and Low findings outside packaging and CI.
- 2026-09-30: Audit follow-up on packaging and CI: every .deb since
  1.0.0 shipped non-root owners; fixed at build time and repaired by the
  postinst on upgrade, with CI ownership checks; the `lorica` crate's
  tests now run in CI.
- 2026-09-30: Review. Five audits on the whole story, both fix passes
  landed, full Docker e2e suite green with zero failures, product tests
  2975. The CLI password finding (backlog #90) is pre-existing and is
  fixed in its own change in this cycle. Status to Done.
- 2026-09-30: Backlog #90, surfaced by this story's security audit: the
  management CLI pins the certificate the management listener records
  as served (`<data-dir>/management/served-cert.pem`) and sends no
  password to a peer presenting another one; a caller who cannot read
  the record is refused. The `mcp` e2e smoke mounts the node's data
  directory read-only so its real minting commands keep running.
- 2026-09-30: Pre-merge audit fixes, automation plane (six audits over
  the release branch). Safe direction only on the config tier (the
  maintainer's decision of the day): `ROUTE_PROTECTIONS` and
  `BACKEND_PROTECTIONS` in `automation/write.rs`, weighed in the guard
  on the stored row against the row to be written, previews included;
  `basic_auth_password` joins the withheld route fields, declared once
  as `WITHHELD_ROUTE_FIELDS` with their reasons; the Basic-auth username
  leaves the tools. A certificate a route write binds anew is weighed
  against the hostname grant; the `environment_protected` binding holds
  on the route path. Each automation request, its audit row and the
  post-commit tail of the write it carries run as a task the connection
  does not own, and the dashboard's shared write bodies the same way; a
  quarter of the audit queue is kept from read and refused rows. The
  OIDC replay set keeps an id until `exp` plus the leeway, and JWKS keys
  published for another use or algorithm are left out; an ID token never
  carries `settings:write`. Write and MCP budgets are keyed per issuer
  entry and project. The retention ceiling of the admin tier is ten
  times the shipped default. The route listing reads its links in one
  query and pages before building views, the SLA overview skips the
  routes before its window, and the log read skips the match count.
  `READ_SURFACE` is held to the router by a test. The self-signed pair
  is generated once per process and a mismatched pair regenerated.
  `[Unreleased]` rewritten as the release's final state. Deferred items
  are backlog #91 to #95. The CLI, packaging and CI findings were fixed
  in a separate pass.
