# Story 11.3: The Admin Tier, and Where It Stops

**Epic:** [Epic 11 - Management MCP Server with Tiered Access (v1.9.0)](../prd/epic-11-v1.9.0.md)
**Status:** Draft
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
settings model carries 81 fields; eighteen are in.

**Retention and purge.** `access_log_retention`, `waf_event_retention`,
`sla_purge_enabled`, `sla_purge_retention_days`, `sla_purge_schedule`.

**Alert and protection thresholds.** `cert_warning_days`,
`cert_critical_days`, `flood_threshold_rps`, `flood_strict_rps`,
`waf_ban_threshold`, `waf_ban_duration_s`.

**Timeouts and probe budgets.** `header_timeout_s`,
`default_health_check_interval_s`, `max_active_probes`,
`health_max_concurrent_probes`, `loadtest_max_concurrency`,
`loadtest_max_duration_s`, `loadtest_max_rps`.

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

*Out although it looks like retention.* `audit_log_retention_days`.
Shortening it destroys the trail this epic depends on to tell a model's
actions from a person's. Retention that protects the audit of the tier
changing it is not a setting that tier may change.

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
      Decided 2026-09-23; the list and the exclusion reasons are above.
      Eighteen of eighty-one fields are in.
- [ ] The allowlist as one table in code, with IV1 asserting the tool
      list against it. The eighteen entries live in exactly one place:
      a second copy beside the tools is the transcription this project
      treats as a defect rather than a style question.
- [ ] The scope or scopes the tier stands on, and the automation-plane
      settings endpoints behind them. As in Stories 11.1 and 11.2, the
      plane does not serve this today.
- [ ] AC #2: a test proving enrolment, revocation and break-glass are
      unreachable through this tier, at the scope check.
- [ ] IV1 as an exact list assertion, derived from the allowlist rather
      than transcribed beside it.
- [ ] IV2: the refusal happens at the scope gate, so the tool does not
      exist to be called rather than existing and saying no.
- [ ] AC #4: audit, `docs/mcp.md`, and the hardening-guide paragraph.

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

## Dev Agent Record

### Debug Log

### Completion Notes

## File List

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
