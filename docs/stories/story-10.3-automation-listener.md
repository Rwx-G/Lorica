# Story 10.3: Automation Listener and Scoped API Tokens

**Epic:** [Epic 10 - Conditional Request Capture & CI Automation API (v1.8.0)](../prd/epic-10-v1.8.0.md)
**Status:** InProgress
**Priority:** P0
**Author:** Romain G.
**Depends on:** nothing in this epic.
**Blocks:** Story 10.4, which is the only resource this listener serves, and Story 10.5, which replaces its credential.

---

As a platform engineer,
I want a network-reachable, token-authenticated API surface that a CI runner can call,
so that pipelines can configure Lorica without the management port ever leaving loopback.

## Problem

The management API binds loopback and authenticates with a session cookie.
A CI runner is neither on loopback nor holding a cookie. Every way of
bridging that gap by widening the management plane is worse than the
problem: a management port on the network, a service account with a
dashboard session, a reverse proxy in front of the proxy.

The answer is a second door that is narrow by construction. Different
port, different credential, different router, and a scope set that does
not contain the management API's verbs.

## Corrections to the PRD

Three statements in the epic do not match this codebase. They are
corrected here rather than discovered during implementation.

**1. There is no `[automation]` settings block, because there is no
settings file.** This project has no TOML configuration and no `--config`
flag: the CLI is pure clap, and everything else lives in the SQLite
`GlobalSettings` row. So the listener's bind address is a clap flag, which
it has to be since it is needed to bind, and `automation_allowed_cidrs`
and the budgets are `GlobalSettings` columns, which gets them hot reload
through `commit_prepared_reload` for free, exactly as
`connection_allow_cidrs` already has it.

**2. `validate_cluster_listen` cannot be reused verbatim.** It hardcodes
three flag names in its error messages and always derives a second
enrollment bind. What is reusable is the pair of private helpers inside
it, `parse_cluster_bind` and `refuse_reserved`. Those are lifted into one
validator parameterised by flag name, and `validate_cluster_listen` is
rewritten to call it, so there is ONE definition of a refused bind rather
than a second copy that drifts. `ReservedPorts` gains the cluster and
automation ports at the same time: today nothing stops an automation bind
from colliding with the cluster port, because the struct only knows about
management, http and https.

**3. The listener belongs to `lorica-api`, not to the binary.**
`build_management_server_config` is `pub(crate)` there, and the accept
loop the management server uses (a manual loop over `TcpListener` and
`TlsAcceptor` feeding `hyper-util`, not `axum::serve`) is the shape to
copy. Making that function public so a caller in another crate could reach
it would be the wrong direction. `lorica-api` already depends on
`lorica-cluster`, `ring` and `ipnet`, so the pre-auth budgets and the CIDR
parsing are in reach.

## What this changes that is not obvious

**No axum listener in this project has ever filtered by source address.**
`ConnectionFilterPolicy` is consulted in the pingora L4 accept loop, which
the management server does not use. So the automation loop performs the
check itself, on the accepted `TcpStream`, before handing it to the TLS
acceptor. That satisfies "closed before the handshake" literally.

To avoid a second copy of the predicate, the pure policy (`from_cidrs`,
`accepts`, and its parsing) moves to `lorica-config`, where both callers
can reach it. `GlobalConnectionFilter`, which carries the `ArcSwap`, the
per-IP counters and the pingora trait implementation, stays in the binary.
That is the natural seam: one of those two things is a rule, the other is
a runtime.

**An automation token is not a join token.** The cluster token carries a
32-byte pin of the control plane's leaf key, which has no meaning here. It
gets its own mint and parse with the same discipline (HMAC-SHA256 of the
secret, constant-time verify, a dummy digest so an unknown `public_id`
costs the same as a known one, the shape checked before any store access)
and its own HMAC key row, so rotating one credential family does not
touch the other.

## Acceptance Criteria

1. **A separate listener, off by default.** `--automation-listen <host:port>` starts a second axum server with its own TLS config, its own router and none of the session middleware. A bare port is refused, `0.0.0.0` and `::` are refused without `--automation-listen-any`, a bind equal to the management, proxy or cluster port is refused, and the effective address is logged at WARN on startup. Hot upgrade hands the listener off with the others.

2. **Cluster placement.** The listener runs on a standalone node or on a control plane. A node holding a follower identity started with `--automation-listen` refuses to start, naming the control plane, because a follower's configuration is replaced on the next replication and any automation write there would be silently lost. The check is the one the cluster plane already uses at startup: a follower identity in the store.

3. **Source allowlist at the listener.** `automation_allowed_cidrs`, mandatory and non-empty when the listener is enabled, evaluated on the accepted socket before the TLS handshake; a connection from outside is dropped with no bytes read. Listener-level connection caps and a sliding-window per-IP limiter reusing `SourceGate` and `AttemptWindow` from `lorica-cluster::preauth`, held across the handshake the way the enrollment listener holds them.

4. **Scoped API tokens.** New `api_tokens` table and `AutomationToken` model. Shape `<public_id>.<secret>`: 256 bits of generated entropy, shown once at creation, stored as HMAC-SHA256 under a dedicated server-side key, verified in constant time with identical timing whether `public_id` exists or not. Fields: `name`, `scopes`, `allowed_hostnames` (exact hostnames or single-label wildcards, matched with `pattern_matches` / `specificity` from `cert_export_acl.rs`), `allowed_backend_cidrs`, `max_ttl` (default 7 days), `expires_at` (default 1 year, mandatory), `last_used_at`, `revoked_at`.

5. **Scopes are a closed enum:** `environments:write`, `environments:read`, `routes:read`, `certificates:read`. No `routes:write`, no `certificates:write`, no `settings:*` in 1.8.0. The automation surface is the environment resource, not the management API behind a different door. Epic 11 revisits this for a different caller with its own justification; the exclusion stands for the CI caller this story serves.

6. **Token administration is management-API only.** `GET|POST /api/v1/automation/tokens`, `DELETE /api/v1/automation/tokens/{public_id}` (revoke), all SuperAdmin, all audited, plus a dashboard sub-page under Settings. Tokens are never creatable through the automation listener itself. Revocation is immediate: an in-flight request holding a revoked token fails its next authorisation check.

7. **Authentication is `Authorization: Bearer <token>` only.** No cookies, and therefore no CSRF question, because there is no ambient credential. Every request is audited with the token `public_id` and name, source IP, method, path and outcome, and `lorica_automation_requests_total{outcome}` increments.

8. **The token never appears in argv or logs.** `lorica automation token create` prints the token once to stdout and nothing else; server-side logs record the `public_id` only; the OpenAPI document marks the scheme `bearerAuth` with a description pointing at GitLab masked variables.

9. **One definition of a refused bind.** After this story, `validate_cluster_listen` and the automation validator share the same primitives, and a test asserts that all three listener families refuse a bare port, an unspecified address without the opt-in, and a port already taken by another listener.

## Integration Verification

- **IV1:** A request to the automation port from outside `automation_allowed_cidrs` is closed before the TLS handshake completes; one from inside with no token gets 401 with `WWW-Authenticate: Bearer realm="lorica-automation"`; one with a revoked token gets 401 and an audit row.
- **IV2:** A dashboard session cookie presented to the automation port is ignored (401), and a valid automation token presented to the management port is ignored (401), proving the two planes share no credential.
- **IV3:** A follower started with `--automation-listen` exits non-zero with the documented message; the control plane in the `cluster` e2e profile serves it, and the resulting environment replicates to both followers.
- **IV4:** An unknown `public_id` and a known one with a wrong secret take indistinguishable time, asserted the way the join-token path asserts it.

## Tasks

- [x] The bind validator: lift the primitives, parameterise by flag name, widen `ReservedPorts`, rewrite `validate_cluster_listen` on top of it (AC #1, #9). The opt-in flag is NOT derived from the flag name: `--cluster-enrollment-listen` shares `--cluster-listen-any`, so a derivation would have named a flag that does not exist. The caller passes the flag, the opt-in and the subject.
- [x] Move the pure `ConnectionFilterPolicy` to `lorica-config`, leaving the runtime in the binary. Done together with backlog #88: four hand-rolled CIDR parsers now delegate to one, and `GlobalSettings::cidr_lists()` is the single enumeration a test guards. That move brings `ipnet` into `lorica-config`, and when it does, Story 10.1's `validate_cidr` (written without it, because the crate had no CIDR parser) must be folded onto the same parser. Two answers to "is this a CIDR" in one crate is the drift this story exists to avoid. They differ deliberately in what they do with a bad entry, the filter warns and skips while a write-time validator refuses, but they must agree on what a bad entry IS.
- [x] AC #4: the token model, its migration, its own HMAC key row, mint, parse and constant-time verify.
- [x] AC #1/#3: the listener, its TLS, its accept loop with the source check and the pre-auth budgets. Nothing starts it yet; the startup wiring is its own slice.
- [x] AC #5/#7: the scope enum, the bearer middleware (not an extractor: an extractor runs after the scope gate and cannot feed it), the per-request audit. The counter is owed, named in the Debug Log.
- [x] AC #2: the follower refusal at startup.
- [x] AC #6: the management-API token endpoints and the dashboard sub-page. The plane-separation test asserts 403, not 404: the scope gate wraps the whole automation router, so an undeclared path is refused before routing resolves.
- [x] AC #8: the CLI helper and the OpenAPI security scheme, in a separate `openapi-automation.yaml` with its own contract gate that cross-checks `x-required-scope` against `required_scope`.
- [x] Hot upgrade: the seven plumbing points. Point four was blocked one slice and closed the next: `start_automation_server` had no inherited-listener parameter, so the producer side deliberately handed over nothing rather than a socket the new side could only close, and the consequence (EADDRINUSE during the overlap) was stated rather than hidden.
- [ ] `docs/automation.md`, written once Stories 10.4 and 10.5 have settled the shapes it describes.
- [ ] Gates: the three CI clippy commands with `RUSTFLAGS=-D warnings`, every Rust suite, `cargo audit`, the frontend three.

## Dev Notes

### An undeclared path must be reachable by nobody

The first implementation defaulted an unlisted path to the widest scope
and called it fail-closed. It is not. A route added without a scope
declaration would stay reachable by exactly the tokens that can do the
most damage, and nothing would say so. `required_scope` returns an
`Option` now: `None` refuses every token and logs at ERROR, so a missing
declaration surfaces as a 403 on the first call instead of as a grant
nobody chose.

### Owed by this story, not yet done

The startup wiring that builds the listener config from
`--automation-listen` and `automation_allowed_cidrs` and starts the
server. The hot-upgrade plumbing, all seven points. The metrics, which
the listener wants and does not have:
`lorica_automation_requests_total{outcome}`,
`lorica_automation_source_refused_total`, and one counter each for the
three pre-auth refusals. A separate OpenAPI document for this plane,
which Story 10.4 needs anyway. And the `ConnectionFilterPolicy` move
into `lorica-config`, which would let the listener share the CIDR parser
rather than using `ipnet` directly.

### The thing most likely to go wrong

`partition_inherited_fds` has a catch-all that files anything not matching
a known prefix into `proxy`. A new listener whose arm is missing does not
fail loudly: its socket silently becomes a proxy listener after the first
hot upgrade. The arm and its test come before anything else in the hot
upgrade work.

### The second thing

A scope check that exists on the router but not on the handler, or on
three verbs out of four. The extractor returns the token's scopes and
every handler asserts the one it needs; the test enumerates the matrix
rather than sampling it.

## Dev Agent Record

### Debug Log

(empty)

### Completion Notes

(empty)

## File List

Anticipated, to be corrected during implementation.

- `lorica/src/cli.rs` (the shared validator, the flags, `hot_upgrade_argv`), `lorica/src/startup/hot_upgrade.rs`, `startup/supervisor.rs`, `startup/single.rs`
- `lorica/src/connection_filter.rs` and `lorica-config/src/connection_policy.rs` (new home for the pure policy)
- `lorica-config/src/models/automation_token.rs`, `store/automation_token.rs`
- `lorica-api/src/automation/` (new: listener, router, bearer extractor, scopes), `lorica-api/src/management_tls.rs`
- `lorica-dashboard/frontend/` (the token sub-page)
- `docs/automation.md` (new), `CHANGELOG.md`

## Change Log

- 2026-09-16: Story drafted from the Epic 10 PRD, after mapping the listener seams. Three PRD statements corrected: there is no settings file to add an `[automation]` block to, `validate_cluster_listen` is not reusable as written, and the listener belongs in `lorica-api` rather than the binary. Added AC #9 and IV4.
