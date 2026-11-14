# Story 12.0: The nginx importer stops misreading `stream {}` blocks

**Epic:** [Epic 12 - TCP and UDP Stream Proxying (v1.11.0 and v1.12.0)](../prd/epic-12-v1.11.0.md)
**Status:** Review
**Priority:** P1
**Author:** Romain G.
**Depends on:** nothing. First story of the 1.11.0 cycle after the `lorica-fleet` extraction.
**Blocks:** Story 12.17 (full stream import consumes the stream-shaped parse results added here).

---

As an operator importing an existing nginx configuration,
I want a `stream {}` block to be recognised as what it is,
so that a TLS passthrough on 443 is never imported as an HTTP route, and a database port does not produce a misleading "use a subdomain on 443" hint.

## Problem

`lorica-dashboard/frontend/src/lib/nginx-parser.ts` recognises `server` and `upstream` with no parent check, so a stream `server` and its `upstream` land in the HTTP-shaped output. A TLS passthrough (`ssl_preread on; proxy_pass tls;` on 443) becomes an HTTP route with an empty hostname. Separately, `splitStatements` emits `{` as its own token, so the `value.endsWith('{')` fallback never matches and any block opener other than `server`, `upstream`, `location` or `if` pushes no frame: every `http {}` or `stream {}` wrapper ends in a spurious "Unexpected closing brace" error, and an unknown block nested in a `location` closes the location early.

## Acceptance Criteria

These are the PRD's, unchanged. They are the contract.

1. **The failing cases come first**, in `nginx-parser.test.ts`, each naming the layer it checks, committed as expected failures (`it.fails`) so the gates stay green, and flipped to passing in the fix commit:
   - (a) the `ssl_preread` sample above yields no route from `convertToLoricaRoutes`;
   - (b) the sample `stream { upstream db { server 10.0.0.10:5432; } server { listen 5432; proxy_pass db; } }` yields no entry in `parseNginxConfig(...).servers` or `.upstreams`;
   - (c) an `http {}` wrapper and a `stream {}` wrapper produce no "Unexpected closing brace" error.
2. **The parser tracks block context.** `server` and `upstream` inside `stream {}` are parsed into stream-shaped results, distinct from the `http` ones, and are never merged into them.
3. **Every block opener pushes a frame**, so unknown blocks, top-level or nested, close where they should. The dead `endsWith('{')` fallback is removed.
4. **Until Story 12.17 lands, stream results produce a diagnostic, never silence.** Each stream `server` yields a `warning` naming its line and stating it was not imported, in place of the port hint.
5. Existing importer tests pass unchanged.

## Integration Verification

- IV1: A mixed configuration with both `http {}` and `stream {}` imports exactly the HTTP routes it imported before this story, no route for any stream server, one diagnostic per stream server, and no brace error.

## Tasks

- [x] Commit A: the failing cases of AC #1 (a), (b), (c) as `it.fails`, each naming the layer it checks (AC #1)
- [x] Commit B: the fix
  - [x] Block openers detected by the `{` token that follows them; every opener pushes a frame, a bare `{` pushes an anonymous one; the `endsWith('{')` fallback removed (AC #3)
  - [x] A `stream` frame (`http` and every other unknown block get a generic frame); `server` and `upstream` inside `stream {}` parsed into `streamServers` / `streamUpstreams`, exported types `NginxStreamServer` / `NginxStreamUpstream` (AC #2)
  - [x] One `warning` per stream `server`, on its opening line, stating it was not imported; no port hint for stream listeners (AC #4)
  - [x] Flip the AC #1 tests to `it`; add the IV1 test, a test on the stream-shaped results and the diagnostic, and a test on an unknown block nested in a `location` (AC #1, #2, #3, IV1)
  - [x] Existing tests untouched and passing (AC #5)
  - [x] Frontend gates: `npm run check`, `npm run lint`, `npx vitest run`
- [x] Follow-up commit: `mail {}` context (servers and nested blocks skipped, one warning per mail `server`), tests, `CHANGELOG.md` `[Unreleased]` > Fixed entry

## Dev Notes

- Statements come from `splitStatements`, which emits `{` and `}` as their own tokens. A multi-line opener (`server` on one line, `{` on the next) is joined into one line by the continuation accumulator before splitting, because a line with no `;` and no brace is held as pending. So an opener and its `{` are always adjacent in the same statement list, which is what the lookahead relies on. The one shape that escapes it, an opener after a `;` on the same line with its `{` on the next (`listen 80; location /` then `{`), reads the opener as a directive and gives the `{` an anonymous frame: that block's content is lost, but the braces stay balanced (read from the code, not covered by a test).
- Two contexts are distinguished, `stream` and `mail`. A `server` block anywhere outside them keeps today's HTTP reading, so configurations pasted without an `http {}` wrapper (the common case, and every existing test) parse exactly as before.
- Decision (orchestrator, same cycle): `mail {}` gets its own context because it has the same defect as `stream {}`: a mail server on 443 or with `ssl` was read as HTTP and could become a route. Everything inside `mail {}` is skipped, nested blocks included, and each mail `server` yields one `warning` on its opening line saying it was not imported because Lorica does not proxy mail. There are no mail result types: no later story consumes them.
- Stream results are kept on `NginxParseResult` as two extra arrays and never touch `servers` / `upstreams`, so `convertToLoricaRoutes` and the wizard (`Step2Analysis.svelte` counts `servers` and `upstreams`) need no change and cannot see them. An HTTP `proxy_pass` naming a stream-only upstream therefore does not resolve to its servers, which is correct.
- The warning carries the stream server's opening line in its `line` field, which the wizard renders as `L<n>` next to the message.

## Dev Agent Record

### Debug Log

- 2026-11-14, commit A (`31f08922`): the three AC #1 cases as `it.fails`; Vitest reported them as 3 expected failures, every other test green.
- 2026-11-14, commit B: the fix; the three cases flipped to `it`, four tests added. Gates run in `node:22` with `pnpm install --frozen-lockfile` (no lockfile or `package.json` change): `npm run check` 0 errors, `npm run lint` clean, `npx vitest run` 45 files / 801 tests passed.
- 2026-11-14, commit B (`f4fbcd73`) recorded. Follow-up commit: `mail {}` context and three tests (mail server skipped with one warning, no route for a mail server on 443 with `ssl`, IV1 inputs plus a `mail {}` block give the same HTTP routes); the IV1 inputs moved to file scope so both IV1 tests share them. CHANGELOG entry added.

### Completion Notes

- AC #1 to #5 met, IV1 covered by its own test. The IV1 test compares the mixed configuration's routes with those of the same HTTP servers parsed bare, which is the input the importer already handled before this story.
- AC #4 reading: the warning names its line through the diagnostic's `line` field, which the wizard displays as `L<n>`, rather than repeating the number in the message; the message names the stream server's `listen` values instead.
- Wizard: no change. `NginxParseResult` gained two arrays; `Step2Analysis.svelte` counts only `servers` and `upstreams`, which now exclude stream blocks, and shows the new warning with the other diagnostics.
- Exported for Story 12.17: `NginxStreamServer` (`listen`, `proxyPass`, `directives`, `line`) and `NginxStreamUpstream` (`name`, `servers`, `line`), on `NginxParseResult.streamServers` / `.streamUpstreams`.

## File List

- `lorica-dashboard/frontend/src/lib/nginx-parser.ts` (modified)
- `lorica-dashboard/frontend/src/lib/nginx-parser.test.ts` (modified)
- `docs/stories/story-12.0-nginx-stream-blocks.md` (created)
- `CHANGELOG.md` (modified)

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-11-14 | 0.1 | Story drafted from the Epic 12 PRD. Status InProgress. | Romain G. |
| 2026-11-14 | 0.2 | AC #1 failing cases committed as expected failures. | Romain G. |
| 2026-11-14 | 0.3 | Fix implemented, tests flipped and added, gates green. Status Review. | Romain G. |
| 2026-11-14 | 0.4 | `mail {}` servers kept out of the HTTP import with a warning; CHANGELOG entry. Status Review. | Romain G. |
