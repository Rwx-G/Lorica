# Story 11.3: The Admin Tier, and Where It Stops

**Epic:** [Epic 11 - Management MCP Server with Tiered Access (v1.9.0)](../prd/epic-11-v1.9.0.md)
**Status:** Done
**Priority:** P2
**Author:** Romain G.
**Depends on:** Story 11.1, all of it. Not on Story 11.2: this tier is
a third scope set over the same core, not a widening of the config
tier.
**Blocks:** nothing.

---

As a super-admin,
I want the narrowest possible administrative surface from an MCP
client,
so that the operations that can lock me out or expose the fleet stay
deliberate.

## Problem

Every tier so far was defined by what it can reach. This one is
defined by what it refuses, and the refusals are the deliverable. A
tier that grows by accretion, one useful setting at a time, ends up
being the management API with extra steps, which is the outcome the
whole epic is arranged to prevent.

## The allowlist, decided 2026-09-23

AC #1 asks for "a short list decided by exclusion". Here it is. The
settings model, `GlobalSettings`, carries 79 public fields; fifteen were
in on 2026-09-23, and nine are in since the maintainer's decision of
2026-09-28 (see "Revised 2026-09-28" below and the Change Log). The
authoritative list is `SETTINGS_ALLOWLIST` in
`lorica-api/src/automation/write.rs`, each entry with its reason, its
bound and its direction; the list below is the decision as it was
first taken, and the tests pin every restatement against the constant
rather than against this file.

**Retention and purge.** `access_log_retention`, `waf_event_retention`,
`sla_purge_enabled`, `sla_purge_retention_days`, `sla_purge_schedule`.

**Alert and protection thresholds.** `cert_warning_days`,
`cert_critical_days`, `flood_threshold_rps`, `flood_strict_rps`,
`waf_ban_threshold`, `waf_ban_duration_s`.

**Timeouts and probe budgets.** `header_timeout_s`,
`default_health_check_interval_s`, `health_max_concurrent_probes`.

**Diagnostics.** `log_level`.

### Why the exclusions are what they are

AC #3's filter, reversibility from the dashboard by a human who has
lost their MCP client, does most of the work and misses one case worth
naming.

*Out because they can lock the operator out.* `management_port`,
`management_cert_pem_path`, `management_key_pem_path`,
`connection_allow_cidrs`, `connection_deny_cidrs`,
`automation_allowed_cidrs`, `trusted_proxies`. A wrong value here ends
the session that would have fixed it.

*Out because they are credentials or trust anchors.*
`bot_hmac_secret_hex`, `prometheus_scrape_token`, `metrics_require_auth`,
`upgrade_signing_pubkey_path`, and the whole `cert_export_*` family,
which writes key material to disk with ownership and modes attached.

*Out because they are identity policy.* `password_min_length`,
`password_require_complexity`, alongside the user operations AC #1
already excludes.

*Out because reversible is not the same as harmless.* This is the case
the filter misses. `max_global_connections`, `connection_limits_per_ip`
and the `mirror_max_concurrent_*` pair are all reversible from the
dashboard in seconds, and a wrong value takes production traffic down
or silently stops mirroring for as long as it stands. A model reading
attacker-authored text should not be able to reach the data plane's
capacity. The OTLP settings are out for the adjacent reason: they
redirect where telemetry goes, and a redirect is not visibly wrong.

*Out because the dashboard cannot write them.* `max_active_probes`,
`loadtest_max_concurrency`, `loadtest_max_duration_s`,
`loadtest_max_rps`. They were in the list decided on 2026-09-23 and
were taken out on 2026-09-28: `UpdateSettingsRequest` has no field for
any of them, so only a full configuration import writes them and AC
#3's filter, reversibility from the dashboard, is false for them today.
`docs/backlog.md` #89 carries the dashboard write path they need before
they can join.

*Out although it looks like retention.* `audit_log_retention_days`.
Shortening it destroys the trail this epic depends on to tell a model's
actions from a person's. Retention that protects the audit of the tier
changing it is not a setting that tier may change.

### Revised 2026-09-28: safe direction plus bounds

The audit of the first implementation showed that reversible from the
dashboard was still too weak a filter: several values inside the
validators' bounds destroyed evidence, switched a protection off, or
harmed in a way a revert did not undo. The maintainer's decision: a key
stays only when it has a direction that harms nothing, and the plane
enforces that direction and a bound per key, with a 4xx naming the key
and the bound.

*Nine stay, each bounded.* `access_log_retention` and
`waf_event_retention` raise-only, never 0 (unlimited);
`sla_purge_retention_days` raise-only; `cert_warning_days` 14..=365 and
`cert_critical_days` 3..=365, under the existing cross-field rule;
`waf_ban_threshold` 3..=100; `waf_ban_duration_s` at most a day;
`default_health_check_interval_s` 5..=60, far inside the shared cap
of 3600, because a dead backend keeps its traffic for three probes of
whatever interval is set (tightened by the maintainer on review);
`health_max_concurrent_probes` 16..=512. The constant carries the
exact figures.

*Out because either direction harms.* `flood_threshold_rps`: lowered,
every per-IP rate-limited route answers 429; at 0, flood defence is
off.

*Out because the dashboard's form has no field for them.*
`flood_strict_rps` and `header_timeout_s`: AC #3 is false for them, the
same defect as backlog #89, which now names them.

*Out because the only direction is the harmful one.*
`sla_purge_enabled` (off means unbounded growth) and
`sla_purge_schedule` (it only makes purges more frequent).

*Out because it has no safe direction.* `log_level`: raised, it floods
the disk and may write request detail into the logs; lowered, it blinds
the investigation. The stored setting was also inert until this
revision, which wired it to a live filter reload for the dashboard.

### What this list must not become

Every later request to add one entry will be reasonable on its own
terms. The exclusion reasons above are the artefact that makes a
widening a decision with a name on it. Keep the reason beside the
entry, because a future reader needs the reason and the entry alone
will not carry it.

## Acceptance Criteria

These are the PRD's, unchanged. They are the contract.

1. **The tier exists, and its surface is a short list decided by
   exclusion.** Global settings that are operational (retention,
   thresholds, timeouts) are in. User creation, role changes and
   password resets are **out**: an identity system driven by a model
   reading attacker-controlled text is a bad trade at any tier, and the
   dashboard is thirty seconds away.
2. **Cluster mutations are out of this tier in 1.9.0.** Enrolment,
   revocation and break-glass stay human-only, for the same reason
   Story 9.9 gives: those actions are the ones an attacker most wants
   and the ones whose audit matters most.
3. **Everything this tier can change is reversible from the dashboard
   by a human who has lost their MCP client.** A setting that could
   lock the operator out of the management plane is not in the tier.
4. Audit, documentation and a `docs/security/hardening-guide.md`
   paragraph recommending that the admin tier be configured only when a
   task needs it, and removed afterwards.

## Integration Verification

- IV1: The admin tier's tool list matches the documented allowlist
  exactly; a test asserts the list rather than describing it.
- IV2: An attempt to reach a user-management or cluster endpoint
  through the admin tier fails at the scope check, not at a tool that
  exists and refuses.

## Tasks

- [x] Enumerate the settings this tier may change, by walking the
      settings surface and applying AC #3's reversibility filter.
      Decided 2026-09-23 and narrowed on 2026-09-28 (see "Revised
      2026-09-28" above): nine of the 79 fields are in, each with a
      bound and a safe direction.
- [x] The allowlist as one table in code, with IV1 asserting the tool
      list against it. The nine entries live in exactly one place:
      a second copy beside the tools is the transcription this project
      treats as a defect rather than a style question.
- [x] The scope or scopes the tier stands on, and the automation-plane
      settings endpoints behind them. As in Stories 11.1 and 11.2, the
      plane does not serve this today.
- [x] AC #2: a test proving enrolment, revocation and break-glass are
      unreachable through this tier, at the scope check.
- [x] IV1 as an exact list assertion, derived from the allowlist rather
      than transcribed beside it.
- [x] IV2: the refusal happens at the scope gate, so the tool does not
      exist to be called rather than existing and saying no.
- [x] AC #4: audit, `docs/mcp.md`, and the hardening-guide paragraph.

## Dev Notes

### Why the refusal must be at the gate, not in the tool

IV2 distinguishes two failures that look identical to a user and are
not the same at all. A tool that exists and refuses has been offered to
the model, which means it is in the context, which means an injected
instruction can name it and a future change can weaken its check. A
tool that was never registered cannot be named. The scope matrix
already refuses an undeclared path for every token, so the work is to
keep those paths undeclared rather than to add a check.

### The tier that is most tempting to widen

Every request to add one more setting to this tier will be reasonable
on its own terms. The list in this file, once written, is the artefact
that makes widening a decision with a name on it rather than a commit.
Keep the exclusion reason beside each entry, because the reason is what
a later reader needs and the entry alone will not carry it.

### The allowlist must bind at the plane, not in the tool schema

Recorded 2026-09-23 from the architecture audit of Story 11.2. That
story withheld one field from a model (`basic_auth_password`) by
leaving it out of the tool's body vocabulary in `lorica-mcp`. The
automation plane still accepts the field: a token holding the write
scope can send it straight to the path, without the tool. For one
credential-bearing field on a surface a human also uses, that is a
narrowing of what a model is offered, and it is recorded as such.

Copied to this story it would bind nothing. The settings on the list
are the whole of what an admin-tier credential may change, and every
other field of the document is what it must not reach however it
calls.
So the allowlist is enforced on the automation settings path itself:
a body naming any field outside the list is refused by the plane
with the field named, before a validator runs, and the tool schema
restates the same list and is pinned against the plane's list by
a test. The plane is the control; the schema is the affordance.

### Inputs to Story 11.4, recorded 2026-09-28, not implemented here

- **A typed tier with a fallible constructor.** The MCP core recovers a
  tool's tier by name against `ADMIN_MUTATIONS`, by `spec.write()` and
  by string equality on the tier label, and `tier()` returns the
  highest tier registered. 11.4 AC #1 (refuse a token spanning two
  tiers) wants a `Tier` enum as data on `ToolSpec`, set by
  `catalogue()` from the array each tool came from, and the check in a
  fallible `McpServer::sharing` so the stdio binding and the Streamable
  HTTP binding, which builds a server per request, both inherit it. A
  check added to the stdio `main` alone would leave the HTTP endpoint
  serving multi-tier tokens.
- **Hostname and CIDR grants on an admin token.** Minting refuses an
  empty `allowed_hostnames` or `allowed_backend_cidrs`, and neither
  bounds anything on the settings path, so an admin-tier token carries
  grants that mean nothing and the dashboard lists them as its blast
  radius. Relaxing the rule would reopen the hole its error text names
  (an empty CIDR list reads as every address). Decide in 11.4, before
  `lorica mcp token create --tier admin` exists: a grant typed as
  absent for tokens whose every scope is grant-free, refused by
  construction for any grant-bounded scope, or a documented inert
  sentinel pair the CLI mints and the dashboard renders as not
  applicable.

## Dev Agent Record

### Debug Log

- The list decided on 2026-09-23 named nineteen settings under a
  heading that said eighteen (5 + 6 + 7 + 1). With the four the
  dashboard cannot write taken out, fifteen remain, not the fourteen
  the removal decision assumed from the heading's count. The fifteen are
  exactly the list less those four; no entry was dropped to reach a
  number. The prose above says fifteen, and no test or document
  transcribes the count.
- `GlobalSettings` has 79 public fields, not 81; counted off
  `lorica-config/src/models/settings.rs`. The tests derive every count
  they need from the constant or the document instead of stating one.

- 2026-09-28, audit fix pass: the four audit reports (security,
  architecture, quality, debt) were re-verified on the code before each
  fix. The health loop read its interval once at spawn; it now re-reads
  it every cycle, so `default_health_check_interval_s` is `Live`, and
  every entry of the nine is `Live` and `Fleet` (pinned against
  `CanonicalGlobalSettings`). The tier's bound check runs after the
  shared field validators, so a value the dashboard's own validator
  refuses (the interval at 0, the probe budget at 513) answers the
  dashboard's 400 rather than the tier's 422; the whole-stack test
  reads the shared schema to tell the two apart.

### Completion Notes

- **The allowlist** is `SETTINGS_ALLOWLIST: &[AdminSetting]` in
  `lorica-api/src/automation/write.rs`, one entry per setting with a
  `why` beside it. A unit test asserts each entry is a key of
  `GlobalSettings`, a field the dashboard's settings form edits (AC #3,
  read off the form since the 2026-09-28 fix pass), unique, and
  carries a reason.
- **The scope** is `AutomationScope::SettingsWrite`, wire
  `settings:write`. The enum's doc comment, its doctest and the unknown
  scope test used `settings:write` as the canonical refused string; they
  now use `users:write`. `scope_str`, both OpenAPI enums, the dashboard's
  `AutomationScope` union and `automation-scopes.generated.ts` carry it.
  The reversal is recorded beside Story 10.3 AC #5 in
  `docs/prd/epic-10-v1.8.0.md`.
- **The path** is `PUT /automation/v1/settings`, declared in the scope
  matrix for `PUT` alone; nothing under it and no other verb is
  declared, so there is no `GET` of the document. The handler takes the
  body as a JSON object (`SettingsPatch`), refuses the first key outside
  the allowlist with a 403 naming it before any value is read (a key
  not shaped like a field name is described, not echoed), types each
  key alone so a type error names its key (422), then calls
  `crate::settings::update_settings_as`.
- **The split.** `update_settings` is now a wrapper over
  `update_settings_as(state, actor, body, mode, audit_target)` with
  `WriteMode::Apply` and `SettingsAuditTarget::Unnamed`, and answers the
  masked row exactly as before: same validators in the same order, same
  reload, same `settings.update` row with the empty target. In
  `WriteMode::Preview` the body runs every validator, the cross-field
  checks and the syslog TLS build included, and stops before the store,
  the reload, the cleartext warning and the audit row. (The fix pass
  below adds a caller-bounds argument, the no-op skip, the syslog
  condition and the dashboard row's changed keys.)
- **The preview read-scope decision.** The 11.2 rule is that a preview
  needs the read scope of the row it answers, because it answers the
  full row. No settings read path exists on the plane and none was
  added. Instead the settings write answers, on the apply and the
  preview alike, only the allowlisted keys of the document
  (`allowlisted_view`), so the scope that writes those keys reads back
  exactly those keys and nothing else of the document (listener
  addresses, sink destinations, masked secrets). With that projection
  the 11.2 rule is satisfied by `settings:write` itself, and the preview
  needs no second scope. A preview requiring a read scope that no tier
  could hold would have made the preview uncallable for the tier, and
  the admin tier must not carry a read scope beside its write one.
  `a_preview_needs_the_read_scope_of_the_row_it_answers` first
  excluded the settings path by filtering `WRITE_SURFACE` on the scope;
  since the fix pass it asserts the property instead, and
  `the_admin_tier_previews_what_it_writes_and_nothing_else` covers it.
- **Audit.** The request row is the plane's existing one. The
  management-side `settings.update` row, through the same function,
  names the token under the role `automation`, and on this path its
  target id is the sorted, comma-separated list of keys whose stored
  value changed (`SettingsAuditTarget::ChangedKeys`); a key sent with its
  current value is not listed. The payload stays hashed. The dashboard's
  row kept its empty target. (Since the fix pass: `key:old->new` on this
  path, the changed key names on the dashboard's.)
- **The tool.** `lorica-mcp` gains `ADMIN_MUTATIONS`, one `Mutation`
  (`lorica_settings_update` and `_preview`, `PUT /automation/v1/settings`,
  body `settings` of type `SettingsPatch`), built into the catalogue
  beside `MUTATIONS`; no new `Kind`. Its field list `SETTINGS_FIELDS`
  restates the allowlist, because `lorica-mcp` cannot depend on
  `lorica-api`; `the_settings_patch_is_documented_and_offered_as_exactly_the_allowlist`
  in `tests/openapi_contract.rs` diffs it and the documented
  `SettingsPatch` schema against the constant both ways. The server
  names the tier `admin tier` when an admin tool is registered, and its
  startup notice asks an admin-tier token for no other scope.
- **IV1** is `iv1_the_admin_tiers_tools_change_exactly_the_allowlist`
  in `lorica-api/tests/admin_tier.rs`: a `settings:write` token
  registers exactly the catalogue's tools behind that scope, each with
  its counterpart, and the union of their body fields is the allowlist,
  both derived. The whole-stack twin is
  `an_admin_tier_token_lists_the_settings_tools_and_nothing_else`.
- **IV2 and AC #2** are
  `iv2_identity_and_fleet_operations_are_declared_for_no_token_on_any_verb`
  (every management path under users, auth, the automation tokens, the
  cluster's nodes and tokens, `leave` and break-glass, read off
  `src/server.rs`, mirrored onto the plane and asked of the matrix for
  five verbs: `None`) and
  `iv2_no_tool_of_any_tier_calls_an_identity_or_fleet_operation`, plus
  the whole-stack
  `identity_and_fleet_paths_are_refused_at_the_scope_gate_for_every_token`,
  which sends them through the listener with the admin token and with a
  token carrying every scope and reads the undeclared-path refusal.
- **Contract tests.** `tests/openapi_contract.rs` knows the one body
  bounded by an allowlist rather than a struct (`ALLOWLISTED_BODY`): its
  accepted fields are read from the constant, and the walks below the
  top level use `UpdateSettingsRequest`, which is now among the request
  struct sources.
- **Docs.** `docs/mcp.md` has the admin-tier section (the settings
  table, pinned against the constant by
  `the_operator_reference_lists_exactly_the_allowlist_with_its_bounds`, the exclusion
  families, where it stops, the preview and audit behaviour, minting);
  `docs/automation.md` the scope paragraph and "The admin write";
  `docs/security/hardening-guide.md` a new "The MCP Admin Tier"
  subsection and a checklist line; `CHANGELOG.md` one Added and one
  Security entry.
- **Audit fix pass, 2026-09-28 (decisions A, B, C).**
  - *A.* `AdminSetting` carries `min`, `max`, `direction`
    (`Either`/`RaiseOnly`), `reach` (`Fleet`/`Node`) and `takes_effect`
    (`Live`/`Restart`); `bound_text()` and `refusal()` are the one
    rendering. The handler hands `update_settings_as` a check that runs
    under the store lock on the stored and patched documents, on the
    keys the body sets (a `null` sets nothing), and answers 422 naming
    the key, the value and the bound. The docs table
    (`| Setting | Tier bound | Reach | Takes effect |`), the tool's body
    doc and summary, and the `SettingsPatch` `minimum`/`maximum` are
    each pinned against the entries (`tests/admin_tier.rs`,
    `tests/openapi_contract.rs`). AC #3 is asserted against the
    dashboard's settings form itself: every `settingsForm` field bound
    to an editable input in the settings tabs, read off the `.svelte`
    files, not `UpdateSettingsRequest`.
  - *B.* The subscriber's `EnvFilter` sits in a
    `tracing_subscriber::reload::Layer` (`lorica::reload::reloadable_log_filter`,
    no new dependency or feature); `apply_log_level_from_store` is part
    of `apply_per_process_reload_state`, which the supervisor, every
    worker and the single-process node run at boot and on every reload,
    so a stored level reaches every process that logs through the
    existing reload channel. `--log-level` governs until the store is
    read; `RUST_LOG`, when set, pins the filter and the stored level is
    logged as not applied, once per change.
  - *C.* `default_health_check_interval_s` capped at 3600 and
    `waf_ban_duration_s` at 2592000 in the shared validator and the
    published schema; the dashboard's fallback cap on the ban duration
    moved to agree. The interval's `NOTE: bound drift` is closed; the
    ban duration's note, about 0, stays; the certificate note no longer
    claims a missing cross-check.
  - `update_settings_as` skips the store write, the reload and the
    audit row when no stored value changed, on both planes, and builds
    the syslog TLS connector only when the patch names a `syslog_*`
    field. `SettingsAuditTarget` is `ChangedKeys` (the dashboard, names
    only) or `ChangedValues` (the plane, `key:old->new`).
  - `allowlisted_view` masks before projecting. The preview read-scope
    exemption is asserted as a property of the answer (keys equal to
    the write vocabulary) in
    `a_preview_needs_the_read_scope_of_the_row_it_answers`, and the rule
    is stated in `write.rs`'s module doc.
  - The plane budgets writes per credential in `authorized()`, inside
    the scope gate, on both routers: `automation_settings` at
    `RL_SETTINGS_UPDATE` and `automation_write` at `RL_ROUTES_CUD` per
    `RL_WINDOW_S`, keyed on `grant_id`, held in
    `AppState::automation_writes`; `WriteBudget` (429) documented on
    every write operation.
  - `OidcIssuer::validate` refuses `settings:write`.
  - IV2: the families gain `/api/v1/automation/oidc-issuers` and
    `/api/v1/cluster/bans`; path literals are read anchored on
    `"/api/v1/` (and `"/automation/v1/`), each checked for a path's
    shape, with a plausibility floor; the automation plane's own mounted
    paths are swept against the families, and
    `every_write_the_plane_mounts_is_on_the_write_surface` asserts the
    inverse of `WRITE_SURFACE` from `router.rs`.

## File List

- `lorica-config/src/models/automation_token.rs` (modified)
- `lorica-api/src/settings.rs` (modified)
- `lorica-api/src/automation/scope.rs` (modified)
- `lorica-api/src/automation/write.rs` (modified)
- `lorica-api/src/automation/router.rs` (modified)
- `lorica-api/src/tests.rs` (modified)
- `lorica-api/tests/openapi_contract.rs` (modified)
- `lorica-api/tests/admin_tier.rs` (new)
- `lorica-api/openapi-automation.yaml` (modified)
- `lorica-api/openapi.yaml` (modified)
- `lorica-mcp/src/tools.rs` (modified)
- `lorica-mcp/src/server.rs` (modified)
- `lorica-mcp/src/lib.rs` (modified)
- `lorica-dashboard/frontend/src/lib/api.ts` (modified)
- `lorica-dashboard/frontend/src/components/settings-tabs/automation-scopes.generated.ts` (modified)
- `lorica-dashboard/frontend/src/components/settings-tabs/GlobalConfigTab.svelte` (modified)
- `lorica-config/src/models/oidc_issuer.rs` (modified)
- `lorica-api/src/server.rs` (modified)
- `lorica-api/src/acme/tests.rs` (modified)
- `lorica-api/src/automation/audit.rs` (modified)
- `lorica-api/src/automation_tokens/tests.rs` (modified)
- `lorica-api/src/oidc_issuers/tests.rs` (modified)
- `lorica/src/cli.rs` (modified)
- `lorica/src/reload.rs` (modified)
- `lorica/src/health.rs` (modified)
- `lorica/src/startup/mod.rs` (modified)
- `lorica/src/startup/single.rs` (modified)
- `lorica/src/startup/supervisor.rs` (modified)
- `docs/installation.md` (modified)
- `docs/mcp.md` (modified)
- `docs/automation.md` (modified)
- `docs/security/hardening-guide.md` (modified)
- `docs/prd/epic-10-v1.8.0.md` (modified)
- `docs/backlog.md` (modified)
- `docs/stories/story-11.3-admin-tier.md` (modified)
- `CHANGELOG.md` (modified)
- `README.md` (modified, product test count)

## Change Log

- 2026-09-23: Drafted from the Epic 11 PRD. AC #1's allowlist was
  deliberately left empty and marked blocking: it is a product decision
  about blast radius and it belongs to the maintainer, not to whoever
  implements the story.
- 2026-09-23: The allowlist decided, eighteen of eighty-one settings.
  The scope chosen was retention and thresholds plus timeouts and probe
  budgets. Capacity limits, mirroring concurrency and OTLP were offered
  and refused, on the ground that reversible is not the same as
  harmless: a wrong global connection limit is undone in seconds and
  takes traffic down for as long as it stands. `audit_log_retention_days`
  is excluded despite reading as retention, because retention that
  protects the audit of the tier changing it is not that tier's to
  change. The story is unblocked.
- 2026-09-28: The allowlist narrowed to fifteen by the maintainer's
  decision. `max_active_probes`, `loadtest_max_concurrency`,
  `loadtest_max_duration_s` and `loadtest_max_rps` are out:
  `UpdateSettingsRequest` has no field for them, so AC #3's
  reversibility-from-the-dashboard filter is false for them today, and
  `docs/backlog.md` #89 records the dashboard write path they need. The
  decision said fourteen, from the heading's count of eighteen; the list
  under that heading named nineteen, so fifteen remain. The field count
  is corrected from 81 to 79.
- 2026-09-28: Implemented. One scope, `settings:write`; one path,
  `PUT /automation/v1/settings`, bounded by `SETTINGS_ALLOWLIST` at the
  plane; `update_settings_as` split out of the management handler; one
  MCP mutation with its preview; IV1, IV2 and AC #2 as tests derived
  from the constant and from the management route table; docs,
  changelog and the hardening-guide paragraph. Status to Review.
- 2026-09-28: Audit fix pass, on the maintainer's decisions of the same
  day. (A) The tier becomes safe direction plus bounds, enforced by the
  plane: nine keys stay, each with a bound, a direction, a reach and a
  takes-effect; six leave (`flood_threshold_rps`, `flood_strict_rps`,
  `header_timeout_s`, `sla_purge_enabled`, `sla_purge_schedule`,
  `log_level`), each with its reason above and beside the constant.
  (B) The stored `log_level` now applies live in every process through
  a reloadable filter and the per-process reload bundle. (C) The shared
  validator caps `default_health_check_interval_s` at 3600 and
  `waf_ban_duration_s` at 30 days on both planes. Also: OIDC issuers
  refuse `settings:write`; a no-op settings write writes nothing; the
  plane budgets writes per credential; the audit row carries
  `key:old->new`; the syslog connector is built only for a syslog
  patch; the IV2 sweep gains two families, a robust parse and its
  inverse. Two inputs recorded for Story 11.4.
- 2026-09-28: Review. The maintainer tightened the tier bound on
  `default_health_check_interval_s` from the shared 1..=3600 to 5..=60,
  because a dead backend keeps its traffic for three probes of the
  interval. Docker e2e suite green on the result, zero failures. Status
  to Done.
- 2026-10-04: Backlog #89 resolved in the 1.9.0 cycle: the dashboard's
  Global Configuration form now writes the six settings this story left
  out because it could not (`max_active_probes`, the three load-test
  ceilings, `flood_strict_rps`, `header_timeout_s`). By maintainer
  decision the allowlist does not change: none of them joined the tier,
  and the exclusion reasons above stay as they were written. The record
  is the closing note of #89 in `docs/backlog.md`.
