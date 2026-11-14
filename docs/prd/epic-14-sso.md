# Epic 14: Single Sign-On for the Management Plane (OIDC and LDAPS)

**Author:** Romain G.
**Target version:** not scheduled. Candidate 1.13.0, after Epic 12 Phase 2 (1.12.0); the maintainer may insert it earlier the way Epic 13 was inserted before Epic 12.
**Status:** Draft (2026-11-14), written against `main` at `459544ee` (v1.10.6); cite function and type names, since line numbers may drift. Not yet reviewed: a requirement challenge, an architecture review against the code and a security review are expected before the first story is drafted. Claims about third-party identity providers marked *(to verify)* come from their documentation as remembered on the day of writing and are checked by Story 14.6 before anything depends on them.

**Epic Goal:** Let an operator sign in to the Lorica dashboard with the identity they already have, from an OpenID Connect provider (authentik, Keycloak, AD FS, Entra ID, any conformant one) or from an LDAP directory over TLS (Active Directory, OpenLDAP, the authentik LDAP outpost), with their Lorica role derived from their group membership. Joining or leaving the operations team becomes a change in the directory, not a ticket to whoever holds the Lorica SuperAdmin password.

**What this epic is not:** it is not about the traffic Lorica proxies. Protecting a proxied application behind authentik or Keycloak is forward authentication, shipped in v1.3.0 (`lorica/src/proxy_wiring/forward_auth.rs`) and unchanged here. It is not about CI either: the GitLab OIDC ID tokens of Story 10.5 authenticate a pipeline on the automation listener, a different plane with a different caller. This epic is the human login to the management plane.

## What exists today

- **Accounts are local.** `lorica_config::models::User` carries a username, an Argon2id hash (`lorica-api/src/auth.rs`, `argon2_hasher`), one `Role` and a `disabled_at`. Usernames are 3 to 32 characters, lowercase alphanumeric plus `._-` (`validate_username`, `lorica-api/src/users.rs`). The first boot creates `admin` with a random password and `must_change_password`.
- **Three roles.** `Viewer`, `Operator`, `SuperAdmin` (`lorica-config/src/models/enums.rs`), with the whole authorization matrix in `required_role` (`lorica-api/src/middleware/authorize.rs`). The users CRUD keeps one invariant: the last enabled SuperAdmin cannot be demoted, disabled or deleted (`count_active_super_admins`).
- **Sessions.** `POST /api/v1/auth/login` issues `lorica_session`, `HttpOnly; Secure; SameSite=Strict; Path=/api` (`session_cookie`, `lorica-api/src/middleware/auth.rs`). A session expires after 30 minutes without a request (`SESSION_TIMEOUT_MINUTES`) and is renewed by every authenticated request, with **no absolute lifetime**. Sessions persist in SQLite and survive a restart. A role change, a disable or a password reset removes every session of the account.
- **The listener.** The management API binds to loopback, port 9443 by default, over TLS (`docs/security.md`, "Management plane authentication"). Operators reach the dashboard through an SSH tunnel or a fronting reverse proxy, which may be Lorica itself. The node therefore does not know the URL the browser uses.
- **Login hygiene.** A per-IP bucket of 5 attempts per 60 s, a dummy Argon2 verify on an unknown username so timing does not reveal which usernames exist, and a deliberate choice not to audit failed logins (`login`, `lorica-api/src/auth.rs`).
- **Accounts never replicate.** `docs/cluster.md`: users, sessions and preferences stay node-local; a compromised control plane cannot push an account to an edge.
- **The CLI logs in with a password.** Every `lorica` subcommand that talks to the local management API takes a username and a password and pins the served certificate (`served-cert.pem`).
- **OIDC building blocks already in the tree.** Story 10.5 verifies JWTs with `jsonwebtoken` (algorithm pinned before any key lookup) and caches key sets behind the `JwksFetcher` trait (`lorica-api/src/automation/oidc/jwks.rs`). Outbound HTTP goes through `lorica_tls::http_client`, the only place `clippy.toml` lets a reqwest client or a rustls `ClientConfig` be built. Secrets are stored in encrypted columns registered in `ENCRYPTED_COLUMNS` (`lorica-config/src/store/mod.rs`). `ring`, `base64` and `rand` are already dependencies of `lorica-api`.
- **No second factor.** Lorica has no TOTP or WebAuthn. Delegating login to an identity provider is also how an operator gets MFA on the dashboard.

## Which protocol for which estate

| Estate | Recommended | Why |
|---|---|---|
| authentik, Keycloak, Zitadel, any OIDC provider | OIDC | The password never reaches Lorica, MFA and session policy stay at the provider. |
| Active Directory with AD FS, or Entra ID | OIDC | Both are OIDC providers; the same code path covers them. |
| Active Directory without AD FS or Entra | LDAPS | The only standard interface the estate exposes. |
| OpenLDAP, FreeIPA, authentik LDAP outpost | LDAPS, or OIDC when the provider has it | |

LDAPS is centralised credentials, not single sign-on: the operator types the directory password into Lorica's login form and Lorica verifies it with a bind. It is in scope because it is the lowest common denominator of Windows estates, and the PRD treats it as the less preferred mode. True Windows single sign-on (the browser's Kerberos ticket, SPNEGO `Negotiate`) is deferred; see "Out of scope".

## Decisions taken up front

**D1 - OIDC Authorization Code flow with PKCE, confidential client, and nothing else.** Lorica is a relying party registered as a confidential client with a client secret, and uses PKCE `S256` on top. No implicit flow, no hybrid flow, no resource-owner password grant. SAML is refused: every provider named in this epic also speaks OIDC, and SAML would bring XML signature verification, a parser surface with a long defect history, for no estate that OIDC does not already cover.

**D2 - The provider is configured by its issuer, and the issuer is pinned.** The SuperAdmin enters the issuer URL, the client id and the client secret. Lorica reads `/.well-known/openid-configuration` over `lorica_tls::http_client`, requires `https`, and requires the document's `issuer` to equal the configured one byte for byte. Endpoints come from discovery and are re-read on a bounded schedule; a change of issuer in the document is a failure, not an update. An optional CA bundle pins the provider's TLS trust, with the same rule as Story 10.5's `ca_pem`: when set, it alone is trusted.

**D3 - ID token validation is strict and the algorithm never comes from the token.** Signature against the provider's JWKS, the algorithm checked against an allowlist before any key lookup (`RS256`, `PS256`, `ES256`; the provider's `id_token_signing_alg_values_supported` must intersect it), `iss`, `aud` containing the client id, `azp` when present, `exp` and `iat` within a bounded skew, `nonce` equal to the one sent. **`HS256` is refused**: an ID token MACed with the client secret proves nothing a stolen client secret cannot forge. authentik signs with the client secret when no signing key is selected on the provider *(to verify)*; `docs/sso.md` tells the operator to select one, and the connection test (Story 14.2) reports the case by name. Claims are taken from the ID token; the UserInfo endpoint is called only when the configured groups claim is absent from it.

**D4 - The flow state lives on the server.** Starting a login creates a pending-flow record holding `state`, `nonce`, the PKCE verifier and the return path, bounded in count and lifetime (10 minutes), single-use. The browser holds only an opaque flow id in a `lorica_oidc_flow` cookie, `HttpOnly; Secure; SameSite=Lax; Path=/api/v1/auth/oidc`. `Lax` is required because the provider returns the browser through a cross-site top-level `GET`, which a `Strict` cookie does not accompany. The session cookie itself stays `Strict`: the callback sets it and answers `303` to the dashboard root, and the dashboard's boot probe `GET /api/v1/auth/me` is a same-origin request that carries it. Story 14.3 pins this sequence in a real browser, because it is the kind of claim that is true in one engine and false in another.

**D5 - Lorica needs to be told its public URL.** The redirect URI is `<management_public_url>/api/v1/auth/oidc/callback`, where `management_public_url` is a new node-local setting: the URL the operator's browser uses to reach this node's dashboard. Lorica never derives it from the `Host` or `X-Forwarded-*` headers of the request, which a client controls. OIDC cannot be enabled while the setting is empty.

**D6 - LDAP is LDAPS or StartTLS, verified, and there is no plaintext mode.** `ldaps://` (implicit TLS) or `ldap://` with StartTLS before any bind; a server that refuses StartTLS fails the connection. Certificate and hostname verification are always on, against the system roots or a configured CA bundle; there is no skip-verify setting. Referrals are not followed. Every operation has a connect, operation and overall timeout. The TLS configuration is built in `lorica-tls`, beside the HTTP client builders, so the `clippy.toml` rule keeps holding.

**D7 - LDAP authentication is search then bind, with a service account.** Lorica binds as a configured service account (DN and password, the password in an encrypted column), searches the configured base with the configured filter, in which `{username}` is replaced by the typed username escaped per RFC 4515, requires **exactly one** entry, then binds as that entry's DN with the typed password on a fresh connection. An empty password is refused before any network traffic: a simple bind with a DN and an empty password is an unauthenticated bind (RFC 4513 section 5.1.2) that many servers answer with success. Direct bind with a DN template is not offered: it cannot read groups without a second identity, and it encourages building a DN from user input.

**D8 - Groups decide the role, and no group means no access.** Each provider carries an ordered list of mappings from a group value to a `Role`: a group name or id from the configured claim for OIDC (default `groups`), a group DN for LDAP (compared after DN normalisation, case-insensitive). The effective role is the highest role any matching mapping grants. **A user who matches no mapping is refused**, with a message saying so; there is no default role, because `Viewer` already exposes the backend topology and the certificate inventory. Nested groups are resolved for Active Directory with the `LDAP_MATCHING_RULE_IN_CHAIN` rule (`1.2.840.113556.1.4.1941`) when the directory type says Active Directory, and through `memberOf` on the user entry otherwise. One role-mapping function serves both protocols and is tested once.

**D9 - External accounts are provisioned on first login and never linked to a local one.** A successful SSO login with a mapped role creates or updates a `User` row with `auth_source` (`local`, `oidc`, `ldap`), the provider id and an immutable external subject: `sub` for OIDC, the entry's `objectGUID` for Active Directory or `entryUUID` for other directories. The subject identifies the account; the username is a display value taken from a configured claim or attribute (default `preferred_username`, `sAMAccountName` on AD), refreshed at each login. A username that collides with an existing account of another source refuses the login and names the collision; Lorica never attaches an external identity to a local account by matching a username or an email address, which is the classic account-takeover path. External usernames follow a wider character set than local ones (`@` for UPNs and emails), still bounded in length and charset.

**D10 - The role of an external account belongs to the provider; its access can still be cut in Lorica.** The role is recomputed at every login and cannot be edited in the users page. A SuperAdmin can **disable** an external account, which takes precedence over the provider and removes its sessions, and can delete it, which only removes the row: a deleted external account is provisioned again at its next successful login, and the users page says so. External accounts have no password, so the password change and reset paths refuse them.

**D11 - A local SuperAdmin always remains: break-glass is permanent.** The last-SuperAdmin invariant counts **enabled local** SuperAdmins. An outage of the provider, an expired client secret or a broken group mapping must never lock the operator out of the node that would fix it, and the CLI, which authenticates with a password (see "What exists today"), keeps a working account. Password login stays available on the login form; restricting it is out of scope.

**D12 - External sessions have an absolute lifetime.** A session opened through OIDC or LDAP keeps the 30-minute idle expiry and gains an absolute lifetime, `sso_session_max_lifetime_minutes`, default 480, bounded. A user removed from the provider, or from the group that granted the role, loses access at the latest when that lifetime ends. Revocation pushed by the provider (OIDC back-channel logout) is deferred. Local sessions keep today's behaviour in this epic.

**D13 - One OIDC provider and one LDAP directory per node, node-local, SuperAdmin-only.** Identity providers are trust anchors that decide who becomes SuperAdmin, so they follow the users they create: node-local, never replicated (the `docs/cluster.md` rule for accounts), and administered by SuperAdmin only, every change audited. On a fleet each node is configured on its own; each node has its own dashboard URL and therefore its own redirect URI anyway. The model keeps a provider id so a later release can add several providers without a migration.

**D14 - Logins are audited whatever the source, failures are counted, not chained.** A successful SSO login records `auth.login` with the method and the provider, like a local one. Failures keep today's rule (not written to the audit chain, which an attacker could otherwise grow) but are logged with a reason category and counted in `lorica_auth_logins_total{method,outcome}`, outcome from a closed set (`success`, `bad_credentials`, `no_role_mapping`, `provider_error`, `flow_invalid`, `username_collision`, `disabled`).

**D15 - An LDAP login cannot be used to lock out directory accounts.** Each LDAP bind with a wrong password counts against the directory's lockout policy, so Lorica is a password-spraying amplifier against Active Directory unless it bounds attempts itself. On top of the per-IP bucket, a per-username failure budget (default 3 failures per 15 minutes) stops Lorica from contacting the directory for that username until it refills. The budget is kept in memory and is per node.

**D16 - Dependencies.** OIDC needs no new crate: `jsonwebtoken`, `ring` (SHA-256 for PKCE), `base64`, `rand` and the shared reqwest client are already there. LDAP needs a client, and the candidate is `ldap3`, used with its rustls feature and a `ClientConfig` built by `lorica-tls` *(feature set and API to verify)*. **Adding it needs the maintainer's approval**, recorded here before Story 14.4 starts. Writing an LDAP client in-house is refused: BER and the LDAP state machine are not where this project should spend its review budget.

**D17 - No new crate.** The OIDC relying party and the LDAP authenticator live in `lorica-api` under `src/sso/`, next to the sessions they create. The JWKS cache of Story 10.5 moves to a module both callers share, with no behaviour change for the automation listener. A separate crate would buy isolation that the code size does not justify and costs the full new-crate checklist of `lorica-rust.md`.

## Story 14.1: External identities in the account model

As a SuperAdmin,
I want the account model to know where an identity comes from,
so that SSO users get sessions, roles and audit entries like local ones without weakening the local accounts.

### Acceptance Criteria

1. **Migration** (number following the last entry of `MIGRATIONS` when the epic starts; Epic 12 claims 71 onward): `users` gains `auth_source` (default `local`), `provider_id`, `external_subject`, with a unique index on `(provider_id, external_subject)`; `password_hash` becomes nullable for external rows only, enforced by a check constraint. A database written by this release opens on the previous minor release, or the PRD records the downgrade path.
2. **The local login path refuses external rows** with the same generic `invalid credentials` and the same Argon2 cost as an unknown user; the password change and the admin reset refuse them with an explicit error (D10).
3. **Role mapping function** (D8), pure, shared by both protocols, with vector tests: highest role wins, no match refuses, empty mapping list refuses, duplicate groups, case rules per protocol.
4. **Break-glass invariant** (D11): `count_active_super_admins` is replaced or complemented so that demoting, disabling or deleting the last enabled **local** SuperAdmin is refused, whatever the number of external SuperAdmins. Tested through the users CRUD.
5. **Absolute session lifetime** for external sessions (D12): the session row stores its source and absolute expiry, `get` refuses a session past it, `renew` never extends it, and a restart preserves it.
6. **Users page**: source and provider shown, role read-only for external rows, disable and delete with the D10 wording.
7. **Audit and metrics** per D14, `auth.login` carrying `method` and `provider_id`.

### Integration Verification

- IV1: Every existing login, session and users-CRUD test passes unchanged.
- IV2: A database upgraded from 1.10.6 keeps its accounts, all `local`, and logs in with the same passwords.

---

## Story 14.2: The OIDC provider configuration

As a SuperAdmin,
I want to register my organisation's OIDC provider and test it before anyone depends on it,
so that a misconfiguration is found in the settings page, not at the next login.

### Acceptance Criteria

1. **Model and store**: issuer, client id, client secret (encrypted column registered in `ENCRYPTED_COLUMNS`, never returned by the API), scopes (default `openid profile email`), username claim, groups claim, role mappings, optional CA bundle (returned as a fingerprint, as `oidc_issuers` does), token endpoint authentication method (`client_secret_basic` default, `client_secret_post`), enabled flag. `management_public_url` setting per D5, node-local.
2. **API** under `/api/v1/identity-providers`, SuperAdmin for every method in `required_role`, every write audited with the secret withheld from `before` and `after`.
3. **Discovery** per D2 through `lorica_tls::http_client`, with `https`, exact issuer match and the D3 algorithm intersection checked at write time and at each refresh.
4. **JWKS cache shared** with Story 10.5 (D17): the module moves, the automation OIDC tests pass unchanged, and the cache keeps its per-URL bounds.
5. **Connection test** reporting each step by name: discovery, issuer match, JWKS fetch, supported algorithms (naming `HS256`-only providers, D3), redirect URI the operator must register at the provider (displayed for copy).
6. **Settings page** section "Single sign-on" with the above, and the redirect URI shown even before the first save.

### Integration Verification

- IV1: Against a mock provider in the test suite, a discovery document whose `issuer` differs by a trailing slash is refused.
- IV2: The client secret appears in no API response, log line or audit row; a test greps all three.

---

## Story 14.3: Signing in with OIDC

As an operator,
I want a "Sign in with <provider>" button on the login page,
so that I reach the dashboard with my organisation's identity and its MFA.

### Acceptance Criteria

1. **`GET /api/v1/auth/oidc/start`** creates the pending flow (D4), sets the flow cookie and answers `303` to the authorization endpoint with `response_type=code`, `state`, `nonce`, `code_challenge` (`S256`), the configured scopes and the D5 redirect URI. Bounded: the pending-flow table refuses new flows past a cap, and the start endpoint shares the login rate limiter.
2. **`GET /api/v1/auth/oidc/callback`** requires the flow cookie, the matching `state` and an unexpired, unused flow; consumes it before anything else; exchanges the code with the PKCE verifier; validates the ID token per D3; resolves the role per D8; provisions or updates the account per D9; refuses a disabled account; creates the session (D12); answers `303` to the return path, which must be a same-origin dashboard path.
3. **Provider errors** (`error=access_denied` and others) and every refusal land on the login page with a message from a closed set, never with the provider's raw text.
4. **Groups claim edge cases**: a claim that is absent, not an array of strings, or an Entra ID overage indicator (`_claim_names`) refuses the login with a message naming the cause; Lorica does not call Microsoft Graph.
5. **Logout**: local logout as today; when the provider publishes `end_session_endpoint`, the dashboard offers "sign out of <provider> too" with `id_token_hint` and a `post_logout_redirect_uri` under D5's URL.
6. **Browser end-to-end test** of D4 in Chromium and Firefox: start, provider login, callback, dashboard loaded with the role, refresh keeps the session, the flow cookie is gone.

### Integration Verification

- IV1: Replaying a callback URL, swapping `state` between two flows, a token with a wrong `nonce`, `aud`, `iss`, `alg`, an `exp` in the past, or an `HS256` signature are each refused, one test per case.
- IV2: The local password login works with OIDC enabled, disabled and with the provider unreachable.

---

## Story 14.4: The LDAP directory configuration

As a SuperAdmin of a Windows estate,
I want to point Lorica at my Active Directory over LDAPS and check it can find a user and their groups,
so that directory logins work the first time.

### Acceptance Criteria

1. **Dependency** per D16, approved and recorded, with `cargo audit` and `cargo deny` clean.
2. **Model and store**: server URLs (tried in order), TLS mode (`ldaps`, `starttls`), optional CA bundle, service account DN and password (encrypted column), user search base and filter template, username attribute, subject attribute (D9), directory type (`active_directory`, `generic`) selecting the group resolution of D8, role mappings by group DN, timeouts, enabled flag. Presets fill the fields for Active Directory, OpenLDAP and the authentik LDAP outpost *(outpost base DN and filter to verify)*.
3. **TLS** per D6, built in `lorica-tls`; a test proves a server presenting a certificate for another name, or signed by an untrusted CA, is refused for both modes.
4. **API and settings page** in the same "Single sign-on" section, SuperAdmin, audited, the password never returned.
5. **Connection test** in steps: connect, TLS, service bind, and an optional lookup of a username given by the SuperAdmin that shows the DN found, the groups resolved and the role they would map to, without binding as that user.

### Integration Verification

- IV1: A filter template without `{username}`, or a username containing `*`, `(`, `)`, `\` or NUL, is handled per RFC 4515: the template is refused at write time, the characters are escaped at login.

---

## Story 14.5: Signing in with LDAP

As an operator in a Windows estate,
I want to sign in with my directory username and password,
so that I do not hold a separate Lorica password.

### Acceptance Criteria

1. **Login resolution**: the existing login form. An existing row is authenticated by its source; an unknown username goes to the directory when LDAP is enabled, and to the dummy Argon2 path otherwise.
2. **Search then bind** per D7, exactly one entry, empty password refused before the network, bind on a fresh connection, no referral followed.
3. **Groups and role** per D8, nested resolution on Active Directory, provisioning per D9, session per D12.
4. **Lockout guard** per D15, with a test that the fourth wrong password within the window never reaches the directory.
5. **Failure categories** per D14; the response to the browser stays the generic `invalid credentials` for every credential failure (unknown user, wrong password, disabled or locked directory account), and `no_role_mapping` is shown as its own message only after a successful bind.

### Integration Verification

- IV1: Against the test directory, a user in a nested group gets the nested group's role on Active Directory semantics and only direct groups on generic semantics.
- IV2: The directory unreachable: local logins work, LDAP logins fail within the configured overall timeout.

---

## Story 14.6: End-to-end, documentation and the release check

As the maintainer,
I want the whole feature tested against real providers and documented per provider,
so that it ships knowing it works with the estates it claims.

### Acceptance Criteria

1. **e2e profile**: a mock OIDC provider written for the suite (signing with a key it generates, able to misbehave on demand) and an OpenLDAP container with the `memberOf` overlay; the Active Directory specific paths are covered by fixtures, since a Samba AD domain controller is out of the suite's budget.
2. **`docs/sso.md`**: the model (D1 to D15 as an operator reads them), break-glass, recipes for authentik (OIDC provider with a signing key selected, groups in the token, and the LDAP outpost), Keycloak, AD FS, Entra ID (and its group overage), Active Directory over LDAPS, OpenLDAP. Each recipe states the provider version it was checked against.
3. **Security documentation**: `docs/security.md` management-plane section and `docs/security/threat-model.md` gain the new trust anchors, the D5 public URL, the D15 lockout guard and what an IdP compromise grants (SuperAdmin on every node that maps it).
4. **README** API table, `COMPARISON.md` row, `CHANGELOG.md` under Added.
5. **Release check by the maintainer** against a real authentik (OIDC and LDAP outpost) and a real Active Directory over LDAPS, before the version bump. Every *(to verify)* in this PRD is resolved there or earlier and its outcome written into "Delivery notes".

---

## Non-functional requirements

- **NFR1 - No change for an operator who configures nothing.** With no provider configured, the login page, the API and every existing test behave as in 1.10.6.
- **NFR2 - A provider outage never reaches the data plane** and never blocks a local login. Every outbound call is bounded in time.
- **NFR3 - No secret in logs, API responses or audit rows**: client secret, service account password, user password, authorization code, ID token, PKCE verifier.
- **NFR4 - Quality gates** as CI runs them (`lorica-rust.md`, `lorica-frontend.md`), coverage of the new modules at or above the project baseline.

## Out of scope

- **SAML.** D1. Refused.
- **Kerberos / SPNEGO single sign-on in the browser.** The truly password-less Windows experience. It needs an acceptor keytab for an `HTTP/` service principal on every node, a browser policy per client, and a deployment where the browser reaches the node by a name the KDC knows. `libgssapi` is already linked since Epic 13, so the cost is integration, not dependency. A candidate once an estate asks for it, and the reason LDAPS is described here as centralised credentials rather than SSO.
- **Several providers per node.** D13. The model keeps the id.
- **Replicating providers across the fleet.** D13.
- **OIDC back-channel and front-channel logout, refresh tokens.** D12 bounds the exposure instead.
- **SSO for the CLI** (device authorization grant). The CLI keeps local accounts (D11).
- **SSO for the automation listener and MCP.** Automation tokens and Story 10.5's ID tokens are unchanged.
- **SCIM provisioning and deprovisioning.** Accounts appear at first login and lose access through D10 and D12.
- **Restricting or hiding the password form.** D11.
- **A local second factor (TOTP, WebAuthn).** Delegated to the provider in this epic; a separate decision for local accounts.

## Open questions for the maintainer

1. Approve `ldap3` (D16), or drop LDAPS from the epic.
2. Target version, and whether the epic goes before or after Epic 12 Phase 2.
3. Default of `sso_session_max_lifetime_minutes` (D12): 480 is a working day; a shorter value costs more round trips to the provider.
