# Story 9.7: Fleet Dashboard

**Epic:** 9 (v1.7.0)
**Status:** Draft
**Author:** Romain G.

**Depends on:** Stories 9.3 (registry, tokens), 9.4 (read-only mode,
break-glass, drift), 9.6 (per-node telemetry).

## Story

As an operator,
I want one dashboard that shows the whole fleet,
so that the single control panel promised by the cluster is usable
without curl.

## Acceptance Criteria

1. New "Cluster" page (Viewer+ read, SuperAdmin for mutations): node
   table with name, address, role, status, version, schema version, last
   seen, applied generation and a drift indicator. Registered in the
   existing `routeLoaders` map. Its gzipped chunk stays under 40 KB.
2. Join-token dialog (SuperAdmin): mints a token, shows it once with an
   explicit warning, and displays a command line using `--token-stdin`
   with the secret in a **separate** copy field.
3. Node detail drawer: health, resource gauges, recent WAF events,
   recent bans, applied hash, certificate inventory with expiry,
   activate action for a `Pending` node, and revoke behind the existing
   `ConfirmDialog`.
4. Read-only mode is orthogonal to role: `canWrite` and `isSuperAdmin`
   are derived over `[auth, nodeMode]`.
5. Node filter on Access Logs, Security and SLA, defaulting to all
   nodes, hidden entirely on a standalone install.
6. A cluster badge showing role and active-versus-expected node count,
   in a warning state on drift, on a stale heartbeat, or while
   break-glass is active.
7. A follower renders a persistent read-only banner naming the control
   plane, and a distinct, louder banner while break-glass is active.
8. Frontend gates green: `pnpm exec svelte-check`, `pnpm tsc --noEmit`
   strict, `pnpm lint`. No `any`, no `@ts-ignore`, no `{@html}`.
   Colocated Vitest files for new components.

## Tasks / Subtasks

- [ ] AC #1: Cluster page + `routeLoaders` entry + node table.
- [ ] AC #2: token dialog with `--token-stdin` command and separate
      secret field.
- [ ] AC #3: node detail drawer with activate and revoke.
- [ ] AC #4: `auth.ts` derived-store change + review pass on all
      consumers.
- [ ] AC #5: node filter on three pages, hidden when standalone.
- [ ] AC #6: header badge with warning states.
- [ ] AC #7: read-only and break-glass banners.
- [ ] AC #8: Vitest files, gates green.

## Dev Notes

**AC #1: lazy loading is already the house style, not a deliverable.**
`routes/Dashboard.svelte:13-25` is a
`Record<string, () => Promise<...>>` of dynamic `import()`s, one per
page, with stale-chunk reload recovery at `:30-41`, and
`lorica-dashboard/frontend/dist/assets/` confirms one chunk per route.
Adding the Cluster page is one line in an existing map.

The first draft carried a "total gzipped bundle within 15% of the v1.6.0
baseline" criterion. It was dropped as both ambiguous and wrong-target:
the initial payload is ~32.6 KB gz (`index-*.js` 27.2 + `index-client`
0.9 + `index-*.css` 4.6), all JS and CSS chunks sum to ~210 KB gz, and
`world-map-*.svg` alone is ~402 KB gz, so "15% of the bundle" could mean
31 KB or 92 KB. More to the point, because chunks are per-route a
standalone install downloads **zero** bytes of the Cluster chunk
regardless of its size, so the budget constrains something no operator
pays. The one real cost of a larger frontend is binary and `.deb` size:
`lorica-dashboard/src/lib.rs:13-15` embeds `frontend/dist` through
`rust-embed` **uncompressed** (no `compression` feature in
`lorica-dashboard/Cargo.toml`), so ~1.9 MB of assets already sits in the
binary. Hence the per-chunk cap instead.

**AC #2 must not undo Story 9.3 AC #6.** The first draft had the
dashboard display the exact `lorica cluster join --token <value>` command
to paste, which guarantees the token reaches shell history, `/proc`, and
any CI or Ansible log that captures argv. The displayed command uses
`--token-stdin`; the secret goes in its own copy field with the
one-time-display warning.

**AC #4 is one edit plus a review pass, not twenty-seven edits.**
`canWrite` (`lorica-dashboard/frontend/src/lib/auth.ts:19`) and
`isSuperAdmin` (`:25`) are two derived stores over a single `auth`
writable, with 27 import sites across 14 files. Deriving both over
`[auth, nodeMode]` changes one file. But the semantics of `canWrite`
then change for every existing consumer, including the read-like actions
Story 9.4 AC #10 promises stay available on a follower: the log export
in `routes/Logs.svelte:6` and the load-test controls in
`routes/LoadTest.svelte:15` are the two to check first. Those sites need
reviewing even though they need no edit, and the review must match the
API allow-list exactly.

**AC #5**: the filter is driven by the per-node stamping from Story 9.6
AC #1 and the endpoints from 9.6 AC #9. It must be genuinely absent, not
merely disabled, on a standalone install, so the standalone UI is
unchanged.

**AC #3** covers the `Pending` lifecycle from Story 9.3 AC #5. A node
that enrolled but was never activated must be visible and actionable, or
the activation gate becomes a support ticket.

## Dev Agent Record

### Debug Log

(empty)

### Completion Notes

(empty)

## File List

Anticipated:

- `lorica-dashboard/frontend/src/routes/Cluster.svelte` (new)
- `lorica-dashboard/frontend/src/routes/Dashboard.svelte`
  (`routeLoaders` entry)
- `lorica-dashboard/frontend/src/lib/auth.ts` (node-mode dimension)
- `lorica-dashboard/frontend/src/lib/components/` (node table, drawer,
  token dialog, banners, badge)
- `lorica-dashboard/frontend/src/routes/{Logs,Security,Sla}.svelte`
  (node filter)
- Colocated `*.test.ts` files

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-08-23 | 0.1 | Story drafted from the revised Epic 9 PRD. Bundle-percentage criterion dropped for a per-chunk cap; token dialog reworked to `--token-stdin`. Status Draft. | Romain G. |
