# Story 8.3: Team Settings - Multi-User RBAC

**Epic:** [Epic 8 - Multi-User RBAC, AI Bot Defense & Zero-Downtime Upgrades (v1.6.0)](../prd/epic-8-v1.6.0.md)
**Status:** Done
**Priority:** P0 (headline)
**Author:** Romain G.
**Depends on:** Story 8.1 (module split, shipped v1.5.10/11); existing single-admin auth stack (`lorica-api/src/auth.rs` + `middleware/auth.rs`).

---

As an operator running Lorica on a shared infrastructure team, I want multiple admin / operator / viewer accounts with role-based access control, so that I can grant junior engineers read-only access without sharing the single admin password and so that audit logs (Story 8.9) carry meaningful operator identity.

## Acceptance Criteria (from the Epic 8 PRD)

1. New `users` table (`id`, `username`, `password_hash` argon2id, `role` enum, `created_at`, `last_login_at`, `disabled_at`, `created_by`); the existing single-admin row is migrated as `username = "admin", role = SuperAdmin` (one-shot DB migration, idempotent).
2. Three built-in roles: `SuperAdmin` (full access + user management + license / settings / encryption-key rotation), `Operator` (full CRUD on routes / backends / certs / WAF / SLA / load-tests / probes / cache / bans, read on settings, NO user management, NO encryption-key rotation), `Viewer` (read-only on everything except secrets - cert private keys, SMTP password, webhook URLs, DNS provider tokens are scrubbed in JSON responses).
3. Login flow: username + password (`POST /api/v1/auth/login` body changes from `{password}` to `{username, password}`; backwards-compat shim accepts the old shape and routes to `username = "admin"`).
4. Session cookie carries the user_id; `Session` extension carries `username + role` so handlers can authorise.
5. New CRUD endpoints under `/api/v1/users` (SuperAdmin only): `GET /users`, `POST /users`, `GET /users/:id`, `PUT /users/:id` (password / role / disabled flag), `DELETE /users/:id` (cannot delete the last SuperAdmin; cannot delete self).
6. Per-handler authorisation: a `require_role!(Operator)` macro on every mutating endpoint; `require_role!(SuperAdmin)` on settings / DNS providers / notification configs / cert-export ACL editing / user CRUD.
7. Dashboard Settings gains a "Users & access" tab: user table (username / role / last login / status / actions) + create-user dialog + change-password dialog + role-change dropdown + disable toggle. Viewer accounts see the dashboard with mutating buttons hidden.
8. Password policy: minimum 14 chars + at least one of each [upper, lower, digit, symbol] (configurable via settings); same hash + verification stack as the existing single-admin (argon2id).
9. Migration path documented in `docs/migrations/v1.6.0-rbac.md` with a one-paragraph operator note explaining the auto-migration of the existing admin password.

## Integration Verification

- IV1: A Viewer-role session calling `POST /api/v1/routes` receives 403; calling `GET /api/v1/routes` succeeds and the JSON has secrets scrubbed.
- IV2: An Operator-role session can create a route but `PUT /api/v1/settings` returns 403.
- IV3: New `tests-e2e-docker/` profile `rbac-smoke` exercises the 3 roles end-to-end (~25 assertions) including the secret-scrub verification; runs in both single-process and workers mode.

## Tasks

- [x] AC #1: `users` table migration (real version gate 22 in `store/mod.rs`, restores the counter), backfill `INSERT ... SELECT` from `admin_users`, drop `admin_users`; `User` model replaces `AdminUser` (adds `role`, `disabled_at`, `created_by`); store CRUD rewritten in `store/users.rs`; `export.rs` scrub follows the rename.
- [x] AC #2: `Role` enum (`SuperAdmin` / `Operator` / `Viewer`) in lorica-config models, TEXT-encoded (`super_admin` / `operator` / `viewer`), decode-tolerant (unknown -> error, not panic).
- [x] AC #3: login accepts `{username, password}` with `username` optional defaulting to `"admin"` (back-compat shim); rejects disabled users; stamps `last_login_at`.
- [x] AC #4: `Session` struct + `sessions` table gain `role`; sessions of a user are invalidated on role change / disable / password reset (immediate effect, mirrors `change_password`); `GET /api/v1/auth/me` returns `{username, role}` and `LoginResponse` gains `role` (frontend boot probe needs it). (CRUD-side invalidation wired in phase 3.)
- [x] AC #5: `lorica-api/src/users.rs` CRUD handlers (SuperAdmin only): list/create/get/update/delete + last-SuperAdmin and self-delete guards; rate-limited; OpenAPI updated.
- [x] AC #6: authorization enforced by a single policy middleware (`middleware/authorize.rs`, see Dev Notes deviation refinement); Operator floor on every mutating endpoint (fail-closed default); SuperAdmin floor on settings writes, DNS providers, notification configs, cert-export ACLs, config import, users CRUD, `POST /system/upgrade`.
- [x] AC #2 (Viewer scrub): Viewer is blocked (403) from the whole `GET /certificates/:id/download` surface (key/full formats live there) and from `POST /config/export` (Operator floor on non-GET); existing unconditional masking (settings `bot_hmac_secret_hex`, notification `********`, DNS-provider write-only credentials) is the remaining Viewer-visible surface.
- [x] AC #8: `password_policy.rs` validator (min length 14 default via new `GlobalSettings.password_min_length`, complexity classes via `password_require_complexity`, default true); applied to login-change, users create/update; frontend mirror in `PasswordChange.svelte` + create-user dialog (replaces the drifted 8/12-char checks).
- [x] AC #7: `UsersAccessTab.svelte` settings section (user table + create dialog + role dropdown + disable toggle + password reset); `auth.ts` store carries `role` (+ `canWrite` / `isSuperAdmin` derived stores); mutating buttons hidden or disabled for Viewer across all pages and settings tabs; global 403 toast handler in `api.ts`; boot probe moved from `/status` to `/auth/me`.
- [x] AC #9: `docs/migrations/v1.6.0-rbac.md` + `docs/security.md` RBAC section.
- [x] IV3: `rbac` + `rbac-workers` compose profiles, `run-rbac-smoke.sh` (37 assertions: 3 roles, 403 matrix, secret scrub, session invalidation, disabled-account handling, last-SuperAdmin + self-delete guards, back-compat login shim), registered in `run.sh` phases + `ALL_PROFILES` + runner Dockerfile. 37/37 green in single-process AND workers mode.
- [x] Gates: product-crate tests (config 197, api 548, waf, notify 60, bench 66) green; CI clippy set clean; `cargo audit` clean (after ammonia bump, separate commit); `svelte-check` 0 errors + `tsc` + `pnpm lint` + vitest 363 clean.

## Dev Notes

### Current auth stack (verified 2026-08-11)

- Login handler `lorica-api/src/auth.rs:72` already takes `{username, password}` (AC #3 is half-done; only the shim, disabled check and role wiring are missing). Argon2id params 19456/2/1 at `auth.rs:25`; `hash_password` at `auth.rs:243`; verify is inlined in `db_blocking` closures (`auth.rs:106`, `auth.rs:207`) - extract a shared `verify_password` helper for reuse by users CRUD.
- `Session` struct at `middleware/auth.rs:21` (`user_id`, `username`, `created_at`, `expires_at`); inserted into request extensions by `require_auth` (`middleware/auth.rs:338`). `SessionStore` is a hybrid in-memory map + SQLite `sessions` table (`019_sessions.sql`), sliding 30-min expiry.
- Bootstrap: `ensure_admin_user` (`auth.rs:286`) creates `admin` with a random 24-char password on first boot, called from `startup/single.rs:74` AND `startup/supervisor.rs:283` (duplicated blocks); plaintext persisted once to `<data_dir>/initial-admin-password` mode 0600.
- Auth is router-wide authentication only: one `require_auth` layer at `server.rs:897`; there is NO authorization anywhere. Public routes: login, logout, `/metrics`, ACME challenge, dashboard assets.

### Migration numbering trap

`schema_migrations` tops out at version 21 but `.sql` files stop at `019_sessions.sql` (file 017 = version 19, inline 018 = version 20, file 019 = version 21); V22-V41 are ungated idempotent `ALTER TABLE` blocks. The `users` table needs a data backfill so it CANNOT be an ungated ALTER: use a real `if current_version < 22` gate + `INSERT INTO schema_migrations VALUES (22)`. Workers open the same DB at boot, so the migration must stay safe under concurrent open (transaction + busy_timeout precedent).

### Design decisions (deviations from PRD letter, not spirit)

- **`require_role!` macro -> single policy middleware** (`middleware/authorize.rs`), a refinement of the per-route-layer plan: per-route layers cannot distinguish methods on a shared `.route(get(x).post(y))` entry without restructuring the router. The final shape is one `authorize` middleware after `require_auth` with the whole matrix in `required_role(method, path)`: `/api/v1/users*` SuperAdmin for all methods; GET/HEAD = Viewer except `certificates/*/download` (Operator); non-GET defaults to Operator (fail-closed for future endpoints) with a SuperAdmin overlay (settings, dns-providers, notifications, cert-export, config/import, system/upgrade) and a Viewer floor on `auth/password`. Unit-tested as a pure function. Known UX trade-off: Viewer PUT on `user_preferences` ("never show again" dialogs) returns 403.
- **Role change / disable takes effect immediately** by deleting all sessions of the target user (pattern already used by `change_password`), not by re-reading the user row per request. A demoted or disabled account is logged out instantly; the session cache stays single-read.
- **`users` table replaces `admin_users`** (backfill + `DROP TABLE`), per AC #1 wording "new users table". The `AdminUser` model and store methods are renamed rather than duplicated; `export.rs` scrub and TOML export follow. Config export archives from pre-1.6.0 remain importable (import maps `admin_users` -> `users` if present).
- **POST-but-not-CRUD endpoints**: `POST /validate/*`, `POST /*/test`, `POST /waf/blocklist/reload`, `POST /loadtest/start*` get Operator floor (they trigger outbound traffic or state reload); `POST /config/export` gets Operator floor (full config disclosure, scrubbed or not, is not Viewer material).
- **Sessions table gains a `role` column** (denormalised like `username`) via ungated idempotent ALTER (V42 style) - no backfill needed, sessions are ephemeral.

### Secret-scrub reality (Viewer surface)

Cert private keys never appear in JSON structs; the leak path is `GET /certificates/:id/download?format=key|full` (`certificates.rs:570-612`) - block for Viewer. SMTP password / webhook url+auth_header are already masked `"********"` for every role (`settings.rs:868`); DNS provider credentials are write-only (`DnsProviderResponse` carries no secret); `bot_hmac_secret_hex` already redacted in `get_settings` (`settings.rs:34`). So the Viewer scrub is: download restriction + config-export restriction + tests pinning the existing masking.

### Password policy

Server-side authoritative validator in `lorica-api/src/password_policy.rs`; the three existing drifted checks (server `>=8` at `auth.rs:179`, frontend `>=12` in `PasswordChange.svelte`) converge on it. New `GlobalSettings` keys `password_min_length` (default 14) and `password_require_complexity` (default true). Length cap stays 128 (argon2 DoS guard).

### Frontend

`auth.ts` is 8 lines (`AuthState` writable, no role) - add `role` to the authenticated state, sourced from `LoginResponse` or `GET /auth/me` on the F5 boot probe (`App.svelte` currently probes `getStatus()` which carries no identity). Settings "tabs" are stacked collapsible Cards in `src/components/settings-tabs/`; `BinaryUpgradeTab` is the cleanest template. Global 401 handler exists at `api.ts:75`; add a 403 handler (toast, no logout). Viewer button-hiding: derive a `canWrite` / `isSuperAdmin` store from `auth` and gate mutating controls.

### e2e

Profile = compose profile + dedicated volumes pair + smoke script (cert-export is the reference shape; ai-bot is the reference for the single+workers dual run). `helpers.sh login()` hardcodes `"username":"admin"` - add a `login_as(user, pass)` variant. Register `rbac` + `rbac-workers` in `run.sh` `ALL_PROFILES` AND the phase list (missing teardown entries leak volumes - Story 8.1 IV2 lesson).

### Worker-mode

Sessions, users and role checks are supervisor-only (`middleware/auth.rs:51` doc); workers never see auth state and `lorica-command` needs no change. The only cross-process concern is the concurrent-migration safety above. The `rbac-workers` e2e profile exists to prove exactly that (management API in supervisor + workers serving traffic).

## Dev Agent Record

### Debug Log

- Phase 1 (config layer): the `V22-V41` comment labels in `store/mod.rs` are ungated ALTERs never recorded in `schema_migrations`; the real recorded version 22 is the users-table gate added at the END of `run_migrations` (after the ungated blocks). Do not renumber the old comments.
- `sessions.role` ships as an ungated idempotent ALTER (default `'super_admin'`, safe: pre-RBAC sessions all belong to the single admin, 30-min TTL).
- Session role staleness is prevented by session invalidation on role change/disable (phase 3 wires the CRUD side); `load_all_sessions` skips rows with unparseable roles instead of failing rehydration.
- Docker gate runs need `MSYS_NO_PATHCONV=1` + Node 22 in the rust container (lorica-dashboard build.rs shells `npm run build`); named volumes `lorica-target-cache` + `lorica-cargo-registry` cache the target dir across runs.
- Full workspace clippy on rust:1-bookworm (clippy 1.95) fails on pre-existing `lorica-proxy` `collapsible_match` - out of CI scope (CI clippy = 5 product crates only).

### Completion Notes

All 9 AC + 3 IV covered across 8 commits (story record, 5 feature phases, e2e, docs) plus the RUSTSEC-2026-0213 ammonia bump surfaced by the pre-commit audit. Two disclosed deviations from the PRD letter, both documented in Dev Notes with rationale: (1) authorization is a single fail-closed policy middleware instead of a per-handler `require_role!` macro; (2) the Viewer secret scrub blocks the certificate-download and config-export surfaces instead of per-field response scrubbing (no secret ever reaches a serialized response struct). e2e gotchas encoded in the smoke: the runner image Dockerfile enumerates smoke scripts explicitly (a new profile must touch compose + run.sh + runner Dockerfile), and the login rate limiter (5/60s per IP) requires waiting out the window before late login assertions. Follow-up candidates for QA: metrics-auth interplay lands in Story 8.8; the audit log consuming `Session.username` lands in Story 8.9.

## File List

Backend:
- lorica-config/src/models/{enums,preferences,settings,mod}.rs (Role enum; User replaces AdminUser; password policy settings)
- lorica-config/src/store/{users,row_helpers,sessions,settings,mod}.rs (users CRUD + count_active_super_admins, v22 migration + backfill, sessions role column, policy keys, clear_all)
- lorica-config/src/{export,import,diff}.rs (users field, legacy admin_users alias, user_eq incl. role/disabled)
- lorica-config/src/tests.rs (role/disabled round-trip, count_active_super_admins, v22 backfill, legacy alias import, schema version 22)
- lorica-api/src/auth.rs (login shim, disabled rejection, LoginResponse role, /auth/me, verify_password helper, policy-driven change_password)
- lorica-api/src/password_policy.rs (new: validator + unit tests)
- lorica-api/src/middleware/{auth.rs, authorize.rs (new), mod.rs} (Session.role; fail-closed policy middleware)
- lorica-api/src/users.rs (new: users CRUD handlers + guards)
- lorica-api/src/{server.rs, lib.rs, tests.rs} (routes + authorize layer + RL_USERS; 10 new integration tests)
- lorica-api/openapi.yaml (login/me/users paths, Role + User schemas, Forbidden response)

Frontend:
- lib/{auth.ts, api.ts} (role store + canWrite/isSuperAdmin; Role/Me/Users types + CRUD + 403 toast; diff field rename)
- App.svelte, routes/{Login,PasswordChange,Settings}.svelte (boot via /auth/me; role propagation; policy mirror; tab registration)
- components/settings-tabs/UsersAccessTab.svelte (new)
- Role sweep: routes/{Routes,Backends,Certificates,LoadTest,Logs,Probes,Security,Sla}.svelte, components/certificates/CertificateList.svelte, components/settings-tabs/{AiCrawlersTab,AppearanceTab,BinaryUpgradeTab,CertExportTab,ExportImportTab,GlobalConfigTab,NetworkTab,ObservabilityTab,PreferencesTab,SecurityPresetsTab}.svelte, components/settings/{SettingsDnsProviders,SettingsNotifications}.svelte

E2E + docs:
- tests-e2e-docker/{docker-compose.yml, run.sh, test-runner/run-rbac-smoke.sh (new)} (rbac + rbac-workers profiles, ~35 assertions)
- docs/migrations/v1.6.0-rbac.md (new), docs/security.md (RBAC section), docs/architecture/data-models-and-schema-changes.md (User model)
- CHANGELOG.md ([Unreleased] Added entry)

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-08-12 | 0.7 | Epic 8 lance-dev closure: full e2e verified this cycle (rbac + rbac-workers 37/37 in both modes, secret-scrub + role floors), CI gates green. No Critical/High open. Status -> Done. | Romain G. |
| 2026-08-11 | 0.1 | Story drafted from Epic 8 PRD + codebase exploration (auth stack, migration numbering trap, scrub surface, e2e profile shape). Design deviations recorded in Dev Notes: middleware factory instead of in-handler macro, session-invalidation instead of per-request role re-read, users table replaces admin_users. | Romain G. |
| 2026-08-11 | 0.6 | Phase 5 (AC #9 + IV3, closure): rbac + rbac-workers e2e profiles (compose, run.sh phase 5, runner Dockerfile registration, 37-assertion smoke incl. rate-limit window wait), migration guide + security.md RBAC section, CHANGELOG entry, run-tests skill CI=true note. Full verification: product-crate tests + CI clippy + cargo audit clean (ammonia bumped 4.1.3->4.1.4 for RUSTSEC-2026-0213), frontend gates clean, e2e 37/37 in both modes. Status -> Review. | Romain G. |
| 2026-08-11 | 0.5 | Phase 4 (AC #7 + AC #8 frontend): `auth.ts` role-aware store + `canWrite`/`isSuperAdmin`, api.ts Role/Me/Users types + users CRUD methods + global 403 toast, App boot via `/auth/me`, Login carries role, PasswordChange mirrors the 14+classes policy, `UsersAccessTab.svelte` (table, create dialog, role dropdown, disable toggle, password reset, self/delete affordances), SuperAdmin-gated in Settings. Role sweep across 20 files: routes pages gated `$canWrite`, settings-write tabs (`/settings*`, dns-providers, notifications, cert-export, config import, binary upgrade) gated `$isSuperAdmin`; read-only exports/filters/WS untouched. Gates: svelte-check 0 errors, tsc clean, eslint clean, vitest 363/363. | Romain G. |
| 2026-08-11 | 0.4 | Phase 3 (AC #5 #6 + Viewer scrub): `middleware/authorize.rs` policy middleware (matrix as pure `required_role(method, path)` fn + 6 unit tests), `users.rs` CRUD (username validation, policy-checked passwords, 409 on duplicate, admin-reset sets must_change_password, session invalidation on role change/disable/password reset, last-SuperAdmin + self-delete guards), `RL_USERS` bucket, OpenAPI (Users paths + User schema + Forbidden response). 5 integration tests incl. demote-invalidates-session and 403-before-lookup on cert download. 548 lorica-api tests green; clippy clean. | Romain G. |
| 2026-08-11 | 0.3 | Phase 2 (AC #3 #4 + AC #8 server side): legacy `{password}` login shim (username optional -> admin), disabled-account 401 post-verify with generic message (no enumeration, no timing oracle), `LoginResponse` gains username+role, `GET /api/v1/auth/me`, shared `verify_password` helper, `password_policy.rs` validator (min 14 via `password_min_length`, complexity via `password_require_complexity`, 128 cap; char-count not bytes), `change_password` now policy-driven (settings read inside the db_blocking closure, current-password check first so wrong-current = 401 not 400), OpenAPI updated (login/me/Role schema). Tests: 5 new integration tests + 7 policy unit tests; 536 lorica-api + 197 lorica-config green; clippy clean. | Romain G. |
| 2026-08-11 | 0.2 | Phase 1 (AC #1 #2 data layer): users table migration v22 with backfill + drop of admin_users, Role enum (PartialOrd floor semantics), User model, store CRUD + count_active_super_admins, sessions role column, Session.role plumbed through SessionStore/login/change_password, export [[users]] + import legacy [[admin_users]] alias, diff rename. Gates: cargo test config+api (197+ tests) green, clippy config+api clean, lorica binary compiles, frontend svelte-check/tsc/lint/vitest (363) green. | Romain G. |
