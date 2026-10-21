# Story 13.2: The AD CS Authority

**Epic:** [Epic 13 - AD CS Certificate Enrollment over CES (v1.10.0)](../prd/epic-13-v1.10.0.md)
**Status:** Review
**Priority:** P0
**Author:** Romain G.
**Depends on:** Story 13.1 (the `lorica-adcs` client: `test_connection`,
`CesParams`, `Secret`, the `krb5.conf` renderer and its typed `Realm`
and `KdcAddress`, `TicketFailure`).
**Blocks:** Stories 13.3 to 13.6. This story owns the schema, the alert
types and the breaker state every later story reads.

---

As a SuperAdmin,
I want to declare my organisation's authority once and see immediately whether Lorica can reach it,
so that issuing a certificate later is one click for an operator and not a debugging session.

## Problem

Story 13.1 produced a client that needs connection parameters and a
password. Nothing stores them, nothing lets anyone enter them, nothing
decides who may change them, and nothing stops a stale password from
locking the service account. The architecture review placed every one
of those responsibilities here, together with the certificate columns
and alert types later stories read, so that 13.3 and 13.4 start from a
schema that exists.

## Decisions taken in this story

**Migration numbers.** `MIGRATIONS` ends at 63 on this branch
(`lorica-config/src/store/mod.rs`). Epic 12 now ships after this epic,
so this story takes the next free numbers and Epic 12 follows. One
additive migration for the authority table and the certificate
columns, one for the alert-type subscription (the migration 63
pattern).

**Breaker state on the authority row, never in a replicated payload.**
D13 already keeps the whole authority out of the canonical blob, so
persisting `failed_since`, `failed_step` and `failed_kdc_code` on the
row costs no replication round.

**The connection test sends no CSR.** Story 13.1 decided that
`test_connection` is an authenticated GET of the endpoint: IIS
authenticates it before WCF refuses the method, so the binding, the
ticket and mutual authentication are exercised and no request reaches
the CA's database.

## Acceptance Criteria

These are the PRD's, unchanged. They are the contract.

1. **Schema, in one additive migration** at the next free version in `MIGRATIONS` (`lorica-config/src/store/mod.rs`): the authority table per D10, and the certificate columns of D14. The authority holds: CES endpoint (`https://` only), realm (`^[A-Z0-9][A-Z0-9.-]*$`), optional explicit KDC list (each `host[:port]` with RFC 1123 labels), service principal, password (own column, registered in `ENCRYPTED_COLUMNS` in the same commit, which the existing source-scan test enforces; write refused without a loaded key per D3), endpoint trust bundle and issuing CA certificate (D12), default template name (the template's common name, not its display name), default key type, subject defaults (`C`, `ST`, `L`, `O`, `OU`, email), allowed DNS suffixes (at least one, D5 semantics, wildcards refused), and the D15 failed state. Any other character in realm or KDC values is refused at the API, with injection test vectors for the `krb5.conf` renderer. The canonical-format change of D14 lands here, with its compatibility test.
2. **Management API** at the paths and roles of D11, with a `required_role` table test for each path. The password is write-only. A change to the endpoint, realm, KDC list or principal clears the password and is refused unless the same request supplies a new one. Deleting the authority while any certificate has `adcs_authority_id` set is refused with the list of those certificates.
3. **Connection test**: acquires a ticket, authenticates to the endpoint with the binding and mutual authentication, and reports success or the failing step from Story 13.1 AC #8. It requests no certificate. Rate-limited per D15, single-flight per D15, refused while the authority is in the failed state, and every test is audited.
4. **Failure state** per D15, persisted, visible on the settings page (since when, which step, KDC code), cleared only by a password write. Entry and exit are audited.
5. **Dashboard settings tab** `AdcsAuthorityTab.svelte` under `components/settings-tabs/`, editable when `$isSuperAdminRole`, read-only for other roles, with the authority-side prerequisites of `docs/adcs.md` linked from the tab. On a follower the tab shows "managed on the control plane" and offers no test button, so `every_path_the_dashboard_offers_on_a_follower_is_still_admitted` stays green.
6. **Cluster** per D13: the authority, its failed state and its issuing CA certificate are absent from the canonical blob and from every follower-facing payload, and a test asserts it.
7. **Export and import** per D14: the authority is not exported.
8. **Audit**: create, update (naming the fields changed, never their values when secret), delete, connection test.
9. **Alert types** `adcs_authority_failed` (one per entry into the failed state) and `cert_issuance_failed` (denial, fault, pending answer, renewal failure; carrying `cert_id` when there is one, the failing step and the authority's message) are added to `AlertType` (`lorica-notify/src/events.rs`), the dashboard's notification settings and history, and `openapi.yaml`. A migration subscribes channels saved with an explicit type list, as migration 63 (`migrate_subscribe_log_store_alerts`) does.

## Integration Verification

- IV1: An Operator token is refused on every authority write, including the suffix list, and admitted on the connection test; a SuperAdmin update of the realm without a password is refused and leaves the stored password unchanged.
- IV2: A connection test with a wrong password, an unreachable KDC, an untrusted endpoint certificate and a missing binding each report a distinct, named failure; the wrong password puts the authority in the failed state after one attempt, and the state survives a restart.

## Tasks

Four lots, each ending on a tree that passes the full gate chain
(fmt, the three CI clippy lines under `RUSTFLAGS=-D warnings`, the
three CI test lines, `cargo audit`, and from Lot 4 the frontend gates
of `.claude/rules/lorica-frontend.md`).

### Lot 1: schema, model, store

- [x] `AdcsAuthority` model in `lorica-config/src/models/` (new file),
      with `AllowedSuffix` (D5 label matching, wildcards refused) and
      the subject defaults; realm and KDC values validated with
      `lorica_adcs::Realm` / `KdcAddress` (so the grammar lives in one
      place) or, if `lorica-config` must not depend on `lorica-adcs`,
      a validator in `lorica-config` pinned to the same vectors by a
      test on each side (`.claude/rules/derived-not-transcribed.md`).
- [x] Migration (next free number): `adcs_authority` table (stable
      `id`, the fields of AC #1, `password_enc`, the failed-state
      columns) and the certificate columns `adcs_authority_id` (plain
      nullable TEXT, no foreign key, D14), `adcs_template`,
      `adcs_template_oid`, `adcs_request_id`.
- [x] `store/adcs_authority.rs` (get, upsert with the at-most-one-row
      rule, delete with the certificate guard, failed-state set/clear),
      `password_enc` registered in `ENCRYPTED_COLUMNS`, and
      `ConfigStore::has_encryption_key()` with a test on
      `open_in_memory`.
- [x] `Certificate` gains the `adcs_*` fields with `#[serde(default)]`;
      `CANONICAL_SHAPE_DIGEST` updated with the backlog #82
      compatibility argument in its comment; a test decodes a blob
      produced without the fields. `acme_auto_renew`'s doc comment says
      it now governs both sources (D14).
- [x] The authority absent from `CanonicalConfig`, `ExportData` and
      every replica path; tests assert it (AC #6, #7).

### Lot 2: alert types

- [x] `AlertType::AdcsAuthorityFailed` and `CertIssuanceFailed` with
      their `as_str` values, the subscription migration, and the
      `openapi.yaml` enum. Dashboard: the notification settings
      checkboxes and history labels.

### Lot 3: API, breaker, audit

- [x] Handlers in `lorica-api/src/adcs.rs` (new), routes in
      `server.rs` with `rl(...)` layers (`adcs_test` at
      `RL_ACME_PROVISION`), `required_role` rules in
      `middleware/authorize.rs`: the SuperAdmin overlay for
      `/api/v1/adcs/authority` writes, the explicit Operator carve-out
      for `POST /api/v1/adcs/authority/test` ahead of it, reads at the
      Viewer default, the follower read-only list unchanged. Table
      test per path.
- [x] Identity-field change clears the password and requires a new
      one in the same request; password write-only; delete guard.
- [x] The breaker: one `AdcsGuard` on the API state (single-flight
      per authority, a `tokio::sync::Mutex` or semaphore), the
      persisted failed state, `TicketFailure::CredentialRejected` as
      the only trigger, `AdcsAuthorityFailed` raised once on entry,
      cleared by a password write.
- [x] The `krb5.conf` regenerated atomically at
      `lorica_adcs::krb5_config_path(data_dir)` on every authority
      write and at startup when an authority exists.
- [x] Audit rows for create, update (field names only), delete,
      connection test, failed-state entry and exit.
- [x] `openapi.yaml` for every path, contract test green.

### Lot 4: dashboard

- [x] `api.ts` types and calls; `AdcsAuthorityTab.svelte` under
      `components/settings-tabs/`, registered in the settings page,
      SuperAdmin-editable, read-only otherwise, follower message, the
      connection test button with the named failure displayed as
      returned, the failed state with since/step/code, the
      prerequisites link. Vitest tests for the role and follower
      behaviour.

## Dev Notes

- DNS providers are the closest precedent for every piece of this
  story: model, store (`store/dns_providers.rs`), encrypted config,
  API (`lorica-api/src/dns_providers.rs`), RBAC
  (`/api/v1/dns-providers` in `middleware/authorize.rs`), test endpoint
  (`/api/v1/dns-providers/{id}/test`). Follow its shape, not its
  replication: DNS providers ride the blob as a digest, the authority
  does not ride it at all (PRD D13, the reason being a low-entropy
  password's unsalted digest).
- `encrypt_*` passes plaintext through when the store has no key
  (`store/mod.rs`); the API store always opens with one, so the
  refusal in AC #1 guards future code, and `has_encryption_key()` is
  new.
- `required_role` resolves by path prefix: a SuperAdmin rule for
  `/api/v1/adcs/authority` would capture `/test` unless the carve-out
  comes first, as capture `disable` does.
- Never log the password, the `Secret`, or a request body of the
  authority endpoints.

## Code Map

- `lorica-config/src/store/mod.rs`: `MIGRATIONS` (ends at 63),
  `ENCRYPTED_COLUMNS`, `migrate_subscribe_log_store_alerts`,
  `encryption_key`.
- `lorica-config/src/canonical.rs`: `CANONICAL_FORMAT_VERSION`,
  `CANONICAL_SHAPE_DIGEST`, the backlog #82 note.
- `lorica-config/src/models/certificate.rs`: `Certificate`,
  `deny_unknown_fields`.
- `lorica-config/src/export.rs`: `ExportData`.
- `lorica-notify/src/events.rs`: `AlertType`.
- `lorica-api/src/server.rs`: `RL_ACME_PROVISION`, route table,
  `rl(...)`.
- `lorica-api/src/middleware/authorize.rs`: `required_role`,
  `follower_read_only`, the follower-offer test.
- `lorica-dashboard/frontend/src/components/settings-tabs/`,
  `lib/api.ts`.

## Dev Agent Record

### Debug Log

- 2026-10-21, Lot 1: `lorica-config` does not depend on `lorica-adcs`
  (it links the system GSS-API library); realm and KDC grammar is
  validated at the API with `lorica_adcs::Realm` / `KdcAddress`, the
  suffix policy (`AllowedSuffix`) lives in `lorica-config`. Key
  rotation now skips NULL text columns, or an authority without a
  password would have failed the whole rotation. Config import returns
  warnings; an AD CS certificate whose authority is absent is imported
  as manual.
- 2026-10-21, Lot 2: migration 65 shares a helper with migration 63.
  The dashboard keeps a hand-typed list of alert types (pre-existing);
  its derivation is scheduled in the epic audit.
- 2026-10-21, Lot 3: refusals (failed state, busy, follower) answer 409;
  the password is required on create. A review found the guard was
  released when the outer timeout fired while a blocking KDC exchange
  kept running; fixed in `200ced18`: every blocking step is awaited,
  the operation runs in a task that owns the guard, the handler answers
  504 when the operation outlives it, and the audit and breaker outcome
  are written when it ends.

### Completion Notes

- AC #1 to #9 met. IV1 covered by the RBAC table and handler tests,
  IV2 by the handler tests plus the Story 13.1 harness.
- `lorica` now links `libgssapi_krb5`, which closed Story 13.1 IV4.

## File List

- `lorica-config/src/models/adcs_authority.rs`, `lorica-config/src/store/adcs_authority.rs`,
  `lorica-config/src/{canonical,export,import,tests}.rs`, `lorica-config/src/store/{mod,certs,replica,cluster_nodes}.rs`,
  `lorica-config/src/models/{mod,certificate}.rs`, `lorica-config/tests/config_db_upgrade.rs`
- `lorica-notify/src/events.rs`, `lorica-notify/src/channels/slack.rs`
- `lorica-api/src/adcs.rs`, `lorica-api/src/adcs/tests.rs`, `lorica-api/src/{server,lib,config,tests}.rs`,
  `lorica-api/src/middleware/authorize.rs`, `lorica-api/openapi.yaml`, `lorica-api/Cargo.toml`,
  certificate literal sites in `lorica-api` and `lorica`
- `lorica/src/startup/{mod,single,supervisor}.rs`
- `lorica-adcs/src/{client,error}.rs`, `lorica-adcs/src/client/tests.rs`, `lorica-adcs/tests/harness.rs`
- `lorica-dashboard/frontend/src/lib/api.ts`, `components/settings-tabs/AdcsAuthorityTab.{svelte,test.ts}`,
  `routes/Settings.svelte`, `components/settings/SettingsNotifications.{svelte,test.ts}`,
  `components/settings-tabs/NotificationHistoryTab.{svelte,test.ts}`

## Change Log

| Date | Version | Description | Author |
|------|---------|-------------|--------|
| 2026-10-21 | 0.1 | Story drafted from the Epic 13 PRD. Status Approved (maintainer delegated the epic). | Romain G. |
| 2026-10-21 | 0.2 | Lots 1 to 4 implemented, guard fix applied. Status Review. | Romain G. |
