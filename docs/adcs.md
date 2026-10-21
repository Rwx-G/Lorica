# AD CS certificate enrollment

**Author:** Romain G.
**Since:** v1.10.0

Lorica can obtain, renew and take over internal certificates from an
Active Directory Certificate Services authority, the way it already does
for Let's Encrypt: the authority is configured once, a certificate is
issued in one confirmed click from the route form or the certificate
page, and it is renewed in place before it expires. It replaces a manual
loop: generate a key and a CSR on a desktop, submit it to the authority,
download the certificate, upload it into Lorica, and do it all again
before expiry.

Lorica talks to the authority's **Certificate Enrollment Web Service**
(CES, MS-WSTEP): SOAP over HTTPS, authenticated with Kerberos SPNEGO
bound to the TLS channel. It generates the key and the CSR itself; only
the CSR crosses the wire, and the private key never leaves Lorica.

An AD CS authority is a domain-wide trust anchor: a certificate it
issues is trusted by every machine in the forest, and its common
misconfigurations are documented attack paths (the ESC1 to ESC8
family). Most of this guide follows from one rule: **Lorica must not be
the weak link of the authority.** Where the authority is misconfigured,
Lorica fails and says why rather than adapting to it.

Throughout, `corp.example.org` is the AD domain, `CORP.EXAMPLE.ORG` its
Kerberos realm, `pki.corp.example.org` the CES host, `<CAName>` the CA's
name and `svc-lorica` the service account. Substitute your own.

## What it does, and what it does not

It does:

- **Issue** a new certificate from the certificate page or from the
  route form, after a confirmation that shows the full request
  (template, key type, complete subject, every name).
- **Renew** AD CS certificates in place, in the same window as ACME
  certificates, with a new key every time, and on demand with "Renew
  now".
- **Adopt** certificates the authority issued before Lorica could, so
  upgrading Lorica ends the manual process instead of running a second
  one beside it; and **revert** any AD CS certificate to manual.
- **Bound the names it may request** with an allowlist of DNS suffixes,
  enforced by the API before anything reaches the authority.
- **Stop at once** when the service account's credential is rejected,
  so a stale password costs one failed pre-authentication, not one per
  certificate per tick.

It does not:

- **Revoke.** CES does not revoke, and neither does Lorica. Revocation
  stays with the authority's administrators. Deleting an AD CS
  certificate in Lorica removes it from Lorica only; it remains valid
  at the authority until they revoke it.
- **Issue or renew from the automation plane or MCP.** Only the
  management plane (the dashboard and its API) issues, and only the
  dashboard and the background loop renew. See
  [What Lorica refuses, and why](#what-lorica-refuses-and-why).
- **Configure Kerberos on the host.** Lorica owns its Kerberos exchange
  end to end; nothing is installed or configured on the host for it.
- **Talk to several authorities.** One authority per installation in
  v1.10.0.
- **Support templates that need a certificate manager's approval.** See
  [Supported templates](#supported-templates).

## The authority side: prerequisites Lorica cannot check

None of these can be verified from Lorica's side. A missing one shows
up as a failed connection test, a refused request, or, worse, as a
deployment that works while weakening the authority. The dashboard's
AD CS settings tab lists them and points here. Hand this section to the
authority's administrators.

### A dedicated certificate template

Create a template for Lorica alone, typically by duplicating *Web
Server*:

- **Subject name: *Supply in the request*.** Lorica sends the subject
  and the subject alternative names in the CSR. With this mode the CA
  takes the subject and the SAN extension from the request, and refuses
  a request with an empty subject; Lorica never sends one (the `CN` is
  always the first name).
- **Extended key usage: *Server Authentication* only.** A template that
  also allows *Client Authentication*, *Any Purpose* or no EKU at all
  lets whoever holds Lorica's credential request a certificate that
  authenticates to the domain (ESC1, ESC2).
- **Enrollment restricted to the service account.** Give *Enroll* to
  `svc-lorica` and remove it from broad groups (*Domain Users*,
  *Authenticated Users*, *Domain Computers*). Lorica bounds names on
  its side, but the template is the authority's own bound, and a
  template anyone may enroll in with *Supply in the request* is ESC1 on
  its own.
- **No CA certificate manager approval**, and no authorised signature
  requirement: Lorica supports templates that issue immediately.
- **Published on the authority.** A template that exists in the
  directory but is not published on this CA is refused as unknown
  (`0x80094800`).
- **Its common name, not its display name.** The CA matches the
  template by its common name (`cn`, the *Template name* field, which
  has no spaces by default); a display name such as "Lorica Web Server"
  fails with `0x80094800`. The authority's *Default template* field in
  Lorica takes the common name, for example `LoricaWebServer`.

**Key type and template version.** A template duplicated from *Web
Server* at schema version 2 uses a legacy cryptographic service
provider that only handles RSA. That is why RSA 2048 is Lorica's
default key type, with RSA 3072 selectable. ECDSA P-256 needs a
template at schema version 3 or later whose cryptography uses a key
storage provider with an ECDSA algorithm. Choose the default key type
on the authority to match the template; a mismatch is refused by the
CA.

### The CA

- **`EDITF_ATTRIBUTESUBJECTALTNAME2` cleared.** With that flag set, the
  CA honours a `san:` request attribute on any template, letting a
  requester add names the template never allowed (ESC6). Lorica never
  sends the attribute, so it does not need the flag; leaving it set
  weakens the authority for every other requester. Check with
  `certutil -getreg policy\EditFlags` on the CA and clear it with
  `certutil -setreg policy\EditFlags -EDITF_ATTRIBUTESUBJECTALTNAME2`
  followed by a restart of the CA service.

### CES

- **A CES instance in Kerberos authentication mode.** Its endpoint
  usually has the form
  `https://pki.corp.example.org/<CAName>_CES_Kerberos/service.svc/CES`.
  An instance in *UsernamePassword* or *Certificate* mode is not one
  Lorica can use.
- **Extended Protection for Authentication set to *Required*** on the
  CES IIS application. Lorica always sends a TLS channel binding, so it
  works either way; *Required* is what makes the binding protect
  anything, because it refuses a relayed or unbound token for every
  client (ESC8 is the relay of a client's authentication to an
  enrollment endpoint).
- **The `HTTP/pki.corp.example.org` SPN registered on the CES
  application pool identity**, and on that identity only. Lorica asks
  the KDC for a service ticket to `HTTP/<host of the endpoint URL>`
  exactly as configured; it does not canonicalise the host through
  reverse DNS. If the endpoint is reached through an alias, the SPN
  must name the alias.
- **A TLS certificate on the CES site** that Lorica can verify: either
  from a CA in the system trust store, or one you paste as the
  authority's *Endpoint CA bundle*, which is then trusted alone for the
  endpoint (see [Configuring the authority](#configuring-the-authority)).

### Accounts

- **AES encryption types enabled** on the service account and on the
  CES pool identity (the *This account supports Kerberos AES 128/256
  bit encryption* options, or `msDS-SupportedEncryptionTypes`). Lorica's
  generated Kerberos configuration permits AES only; RC4 and DES are
  never negotiated, whatever the KDC offers.
- **A service account password that does not expire**, or a documented
  rotation procedure. When the password changes in the directory, a
  SuperAdmin saves the new one in Lorica at the same time. A stale
  password is rejected by the KDC and puts the authority in the
  [failed state](#the-failed-state), which stops every AD CS operation
  until a new password is saved: a deliberate stop, so the account is
  not locked out by repeated attempts. Keytabs are not supported in
  this release.

## The Lorica host

### Network and time

| From Lorica to | Port | What for |
|---|---|---|
| The CES host | TCP 443 (or the port in the endpoint URL) | HTTPS to the enrollment service |
| The KDCs (domain controllers) | TCP and UDP 88 | Kerberos ticket acquisition; TCP is preferred |
| The DNS resolvers | 53 | The endpoint's host, the KDCs' names, and the `_kerberos` SRV records when no KDC list is configured |

Nothing connects to Lorica for this feature.

**Time** must be synchronised with the domain (NTP or `systemd-timesyncd`
pointed at the domain's time source). Kerberos refuses a clock skew
beyond a few minutes (five by default on AD), and the failure shows as a
ticket acquisition error that does not name the clock unless you read
the message.

### Nothing Kerberos to install or configure

- The packages depend on the GSS-API runtime library
  (`libgssapi-krb5-2` on Debian and Ubuntu, `krb5-libs` on Fedora and
  RHEL), which the package manager installs with Lorica. No Kerberos
  client tools (`kinit`, `klist`) are needed, and none are used.
- The host's `/etc/krb5.conf` is **not read**. Lorica generates its own
  file at `<data-dir>/adcs/krb5.conf` (`/var/lib/lorica/adcs/krb5.conf`
  in the shipped unit and image), mode 0600 in a 0700 directory,
  rewritten atomically whenever the authority changes, before every
  operation and at startup. It is rendered from validated fields only:
  the realm, `rdns = false` and no host name canonicalisation, TCP
  preferred, AES encryption types only, a `request_timeout`, and either
  the explicit KDC list or DNS SRV discovery. A realm or KDC value that
  could inject a line into it is refused by the API. Do not edit it:
  the next operation rewrites it.
- No ticket ever reaches the disk. A ticket is acquired in memory for
  one operation (one dashboard action, or one renewal) and discarded
  after it.

### Never give the binary file capabilities or setuid

Lorica points MIT Kerberos at its generated file through the
`KRB5_CONFIG` environment variable, set at the very start of the
process. MIT reads that variable with `secure_getenv`, which **ignores
it in a process started with elevated privileges**: a binary that is
setuid, or that carries file capabilities (`setcap
cap_net_bind_service+ep /usr/bin/lorica`). Lorica would then silently
fall back to the host's `/etc/krb5.conf`, or to none, with whatever
encryption types and KDCs that file names.

The supported way to bind ports below 1024 is the shipped systemd
unit's `AmbientCapabilities=CAP_NET_BIND_SERVICE`, which does not set
the binary's privileges and keeps `KRB5_CONFIG` effective. If you run
Lorica outside the shipped unit, grant the capability the same way
(ambient, from the service manager or container runtime), never with
`setcap` on the file.

## Configuring the authority

The authority lives under **Settings > AD CS authority** in the
dashboard, on the control plane. One authority per installation.

| Field | What it is |
|---|---|
| CES endpoint | `https://` only, with a DNS host name (the service ticket is for `HTTP/<host>`), no credentials in the URL |
| Kerberos realm | Upper case letters, digits, dots and hyphens: `CORP.EXAMPLE.ORG` |
| KDCs | Optional, one `host[:port]` per line (`dc01.corp.example.org`, `dc02.corp.example.org:88`). Empty: discovered through DNS SRV records |
| Service principal | `svc-lorica` or `svc-lorica@CORP.EXAMPLE.ORG`, in the realm above |
| Service account password | Write-only (see below) |
| Endpoint CA bundle | Optional PEM. When set, these certificates alone are trusted for the CES endpoint's TLS certificate, instead of the system and webpki roots |
| Issuing CA certificate | Optional PEM: the CA that signs Lorica's certificates. Learned from the first issuance when left empty; needed for adoption |
| Default template | The template's common name |
| Default key type | RSA 2048 (default), RSA 3072, ECDSA P-256 |
| Subject defaults | `C`, `ST`, `L`, `O`, `OU`, email: the fixed part of every subject. The `CN` is always the certificate's first name |
| Allowed DNS suffixes | At least one; see [The allowlist](#the-allowlist) |
| Auto-renew by default | The auto-renew setting a new certificate starts with |

**The password is write-only.** It is stored encrypted in its own
column under the node's master key (`lorica rotate-key` covers it),
never returned by any read, never logged and never in the audit rows: a
read reports only whether one is set. Leaving the field empty on an
update keeps the stored password.

**Changing where the credential goes clears it.** Any change to the
endpoint, the realm, the KDC list or the principal clears the stored
password, and the same save must supply it again; a save that changes
one of them without a password is refused and leaves everything as it
was. Whoever can redirect where the credential is sent could otherwise
harvest material derived from it: a connection test against a KDC of
their choosing sends pre-authentication derived from the password.

### Who may do what

| Action | Role |
|---|---|
| Read the authority (password reported as set or not) | Viewer |
| Create, change or delete the authority, including the allowed suffixes | SuperAdmin |
| Run the connection test | Operator |
| Issue a certificate, "Renew now", adopt, revert to manual | Operator |

The split is deliberate. An Operator has full control over certificates;
if the same role could edit the allowlist, the allowlist would bound
nothing against the people it exists to bound, and if it could edit the
realm or the KDC list, it could aim the service account's
pre-authentication at a server of its choosing. The limit of that
protection is stated in the threat model: the allowlist bounds callers
of the API, not someone who can read the data directory, where the
master key sits beside the database.

Every write is audited, naming the fields changed and never their
values (`adcs.authority.create`, `adcs.authority.update:<fields>`,
`adcs.authority.delete`).

**Deleting the authority** is refused while any certificate still
references it; the refusal lists them. Revert them to manual or delete
them first.

## The connection test

**Test connection** on the settings tab (Operator and above) acquires a
ticket for the service account, authenticates to the CES endpoint with
the TLS channel binding, and checks the endpoint's mutual-authentication
token, which is the proof that the server holds the service's key. It
requests no certificate: the authenticated request is a `GET` that IIS
authenticates before the service refuses the method, so nothing
reaches the CA's database.

The answer is either "Connection OK" or the failing step and the
client's message, as they are; see
[Troubleshooting](#troubleshooting). Every test is audited
(`adcs.authority.test.ok`, `adcs.authority.test.failed:<step>`,
`adcs.authority.test.refused:<reason>`). The test is rate-limited to 3
a minute, and runs under the same single-flight guard as every other AD
CS operation.

A wrong password puts the authority in the [failed
state](#the-failed-state) **after one attempt**. That is the intended
behaviour, not a test side effect to work around.

Run it after every authority change, and after saving a new password to
leave the failed state.

## Issuing a certificate

Issuance is a human decision: the authority logs it, and only its
administrators can undo it, by revocation. Every issuance from the
dashboard goes through a confirmation that shows the template, the key
type, the complete subject and every name, and the API documents
`POST /api/v1/certificates/adcs` as an issuance.

### From the certificate page

**Certificates > AD CS** opens a form: the DNS names (the first one is
the `CN` and the certificate's domain), and optionally a template, a
key type and subject fields that replace the authority's defaults for
this certificate, plus its auto-renew setting.

A certificate issued here is **not bound to any route**. The renewal
loop only renews certificates a route uses, so it is renewed once a
route uses it; the form says so.

### From the route form

When a route's hostname or aliases are covered by no stored certificate
(checked against every certificate's domain and SANs), the route form
offers **Issue from AD CS**, with those names pre-filled and wildcard
aliases dropped. After the confirmation, a successful issuance selects
the new certificate in the form; the binding is saved with the route.
Cancelling the route's creation afterwards leaves an unbound
certificate, visible on the certificate page.

The action is hidden when no authority is configured, on a follower, and
for roles below Operator.

### The allowlist

Every name is checked against the authority's allowed DNS suffixes
**before the authority is contacted**, so a refused name costs no
Kerberos attempt and leaves nothing at the authority. Names are trimmed,
lowercased, stripped of a trailing dot and deduplicated. An entry permits
that name and every name under it, at any depth; matching is on whole
DNS labels, case-insensitive, never on a string suffix.

With `corp.example.org` allowed:

| Name | Result |
|---|---|
| `corp.example.org` | Permitted |
| `app.corp.example.org` | Permitted |
| `api.eu.corp.example.org` | Permitted (any depth) |
| `APP.Corp.Example.Org` | Permitted (requested as `app.corp.example.org`) |
| `evilcorp.example.org` | Refused: `evilcorp` is not the label `corp` |
| `corp.example.org.attacker.test` | Refused |
| `example.org` | Refused: a parent is not under its child |
| `*.corp.example.org` | Refused: wildcards are refused, whatever the allowlist |

A request may carry at most 100 names. A refusal answers 422
`adcs_san_refused` and names the offending names.

### What happens on each outcome

| Outcome | HTTP | What Lorica does |
|---|---|---|
| Issued | 201 | Checks that the certificate covers every requested name and matches the generated key, stores it with its chain and the encrypted key, records the template observed in it, records the issuing CA certificate on the authority if it had none, and serves it through the hot-swap path. The page shows the subject **as issued**: the authority may rewrite or drop subject fields, and Lorica shows what it received, not what it asked for |
| Pending | 202 | The template needs approval. Nothing is stored, the generated key is discarded, the authority's request identifier is shown, audited and alerted (`cert_issuance_failed`) |
| Denied | 422 `adcs_denied` | Nothing is stored; the authority's message is shown; alerted |
| Fault or client failure | 502 `adcs_error` | Nothing is stored; `error.step` names the failing step and the message says it in words; alerted |
| Refused before contact | 409 or 422 | No authority or no password (`adcs_not_configured`), the failed state (`adcs_failed_state`), another AD CS operation running (`adcs_busy`), a follower; or a refused name or field |
| Still running | 504 | See [Timeouts](#timeouts-and-the-single-flight-guard) |

An issued certificate that does not cover the requested names (step
`san_coverage`) is not stored, and remains valid at the authority until
revoked there: tell its administrators.

Issuance is rate-limited to 3 a minute in its own bucket, and every
attempt is audited under `adcs.certificate.issue` with its names and
outcome.

## Renewal

AD CS certificates are renewed by the same background loop as ACME
certificates, on the control plane, every 12 hours, with the same
**30-day window** and the same binding rule. A certificate is renewed
when all of these hold:

- it is an AD CS certificate (issued by Lorica, or adopted);
- its **Auto-renew** setting is on;
- it has 30 days or less left;
- **a route uses it.** An unbound certificate is never renewed, since
  it is never served.

A renewal is an issuance at the authority, and it is **in place**: the
certificate keeps its id and its route bindings, and the new one
replaces it when it is stored. Each renewal generates a **new key and a
new CSR** (keys are never reused), requests the current certificate's
names and subject again, and uses **the template recorded on the
certificate**, not the authority's current default, which only applies
to new issuance. The key type is the authority's current default.

**"Renew now"** on the certificate page renews an AD CS certificate at
once (Operator and above), after a confirmation, under the same rules
and guard. A second renewal of the same certificate while one is in
flight, from the loop or another click, answers 409. A pending answer is
reported with its request identifier, and the current certificate stays.

**When a renewal fails**, the current certificate stays in service.
Any failure other than a rejected credential, a pending answer included,
leaves that certificate alone for 24 hours before the loop tries again,
and raises `cert_issuance_failed` once per failure state, not on every
tick. A rejected credential opens the [failed state](#the-failed-state)
and ends the tick: the other certificates due are not attempted, so the
tick costs one pre-authentication attempt in all.

**Expiry alerts.** `cert_expiring` comes from the regular expiry check
with the thresholds you set, as for an uploaded certificate; the loop
sends no second expiry alert for AD CS certificates. What it adds is
`cert_issuance_failed` when a renewal fails.

Loop renewals are audited with the actor `adcs-renewal`.

**Not from the automation plane, nor MCP.** A token asking to renew an
AD CS certificate is refused with 403
`adcs_renewal_not_on_automation_plane`, after its grant is checked, so
a token outside its grant learns nothing more. Widening what existing
`certificates:write` tokens can do against a domain-wide authority would
be a decision of its own, and the token renewal budget was reasoned for
Let's Encrypt.

**Auto-renew off** keeps a certificate AD CS-managed with no automatic
renewal; "Renew now" still works. **Revert to manual** (below) takes it
out of AD CS management altogether.

## Adopting certificates issued by hand

Upgrading to v1.10.0 changes no existing certificate: every certificate
stays manual. Lorica offers to take over the ones your authority issued.

**Candidates** are manual certificates whose leaf is signed by the
authority's **issuing CA certificate**, checked by signature and
authority key identifier, never by issuer name and never against a root
(every issuing CA under the same root would match), and whose names all
satisfy the allowlist. Detection needs that issuing CA certificate:
issue one certificate through Lorica, which records it, or paste it in
the authority settings. Until then the certificate page says so.

When candidates exist, the certificate page shows a banner; **Review**
opens the adoption panel, which shows for each certificate:

- the names and the subject renewal will request, taken from the
  certificate itself, not from the authority's defaults;
- the template it was issued with (the template OID of a version 2 or
  later template, or the name of a version 1 template), next to the one
  observed on certificates Lorica issued with the authority's template
  ("unknown" when Lorica has issued none yet), with a warning when they
  differ: the renewal requests the authority's template, so the renewed
  certificate may differ in key usage, validity or subject rules. Check
  with the authority's administrators before adopting;
- its auto-renew setting, starting from the authority's default.

Adopt certificates one by one or select them all (Operator and above).

**Adoption issues nothing.** It marks the certificate as managed by the
authority, with the authority's template recorded for its renewals. The
certificate stays in service as it is, and is renewed in the normal
window once a route uses it, or at once with "Renew now". The CSR kept
from a manual issuance is not needed: a renewal generates a new key and
a new CSR.

### Reverting to manual

**Revert to manual** is available on any AD CS certificate (Operator and
above). Lorica stops renewing it and keeps the current certificate in
service until you replace it. It is distinct from turning auto-renew
off, which keeps the certificate AD CS-managed. Reverting is also how a
certificate stops referencing the authority before the authority is
deleted.

Adoption and reversion are audited, naming the certificates.

## The failed state

A failing credential stops everything at once, and stays stopped.

**What opens it.** The KDC rejecting the service account's credential
during ticket acquisition, in any AD CS operation (connection test,
issuance, "Renew now", the renewal loop):

| KDC code | Name | Usual cause |
|---|---|---|
| 24 | `KDC_ERR_PREAUTH_FAILED` | Wrong password |
| 18 | `KDC_ERR_CLIENT_REVOKED` | Account disabled or locked out |
| 23 | `KDC_ERR_KEY_EXPIRED` | Password expired |
| 31 | `KRB_AP_ERR_BAD_INTEGRITY` | Wrong password on an account that does not require pre-authentication |

Nothing else opens it: an unreachable KDC, a TLS failure or a fault from
the CA are reported and retried later, but they do not suspend the
authority.

**What it stops.** Every AD CS operation against the authority: the
connection test, issuance (409 `adcs_failed_state`), "Renew now" and the
renewal loop, which skips AD CS renewals entirely while it lasts. AD CS
certificates already issued keep being served.

**Why.** Each attempt with a stale password is one more failed
pre-authentication against the account. Retried per certificate per
tick, plus every test and click, it would lock the account in the
directory, and possibly other things that use it.

**What you see.** One `adcs_authority_failed` alert on entry (not one
per refused operation), an audit row
(`adcs.authority.failed_state.enter:<step>`), and a banner on the
settings tab with when it started, the step, and the KDC code with its
meaning. The state is persisted on the authority, so a restart, a crash
loop or a hot upgrade does not spend another attempt.

**How to clear it.** Fix the account in the directory first (reset the
password, unlock or re-enable the account), then have a SuperAdmin
**save the new password** in the authority settings. Saving a password
is the only thing that clears the state (audited as
`adcs.authority.failed_state.exit`). Then run the connection test.
Saving does not test the password: if it is still wrong, the next
operation opens the state again, after one attempt.

## Timeouts and the single-flight guard

**One AD CS operation at a time.** Connection tests, issuance, "Renew
now", loop renewals and authority writes share one guard per process. A
second operation is refused at once with 409 rather than queued: the
Kerberos calls are blocking, and a queue behind a silent KDC would pile
up blocked threads, each about to spend another attempt against the
account.

**The bounds.** An operation has 10 seconds per connection to the CES
host, 30 seconds per read, and 120 seconds in all. The generated
`krb5.conf` bounds each KDC exchange with `request_timeout = 30s`.

**MIT Kerberos before 1.22 ignores `request_timeout`**, as it ignores
`kdc_timeout` and `max_retries`, which are Heimdal settings. On those
releases nothing in the configuration bounds a KDC exchange, and a KDC
that never answers costs MIT's own retry schedule, about **27 seconds
per silent KDC**, measured. With several silent KDCs (an explicit list,
or what SRV discovery returns), the attempts add up. Check the version
with `dpkg -s libgssapi-krb5-2` or `rpm -q krb5-libs`. The remedy is a
KDC list that names reachable domain controllers, or SRV records that do.

**What a handler waits for.** The dashboard's request waits up to 135
seconds (the operation bound plus a grace for the audit and breaker
writes). A Kerberos call cannot be interrupted, so an operation whose
deadline passed during one returns only when that call does. If it
outlives the request, the request answers **504**, and the operation
keeps running in the background, still holding the guard: **every other
AD CS operation answers 409 until it ends.** Its outcome is recorded
when it does: the audit row, the stored certificate for a successful
issuance or renewal, the failed state for a rejected credential. Wait,
then read the audit log or the certificate page rather than retrying.

## In a cluster

AD CS runs on the **control plane only**, which is already where
certificate renewal runs.

- **Followers never hold the authority, its password, its failed state
  or its issuing CA certificate.** The authority is not part of the
  replicated configuration: replicating it would hand every follower the
  endpoint, realm, KDCs, principal and suffixes in clear and an
  offline-crackable digest of a password a person chose, for no drift
  detection the fleet uses. A follower's settings tab shows "managed on
  the control plane", with no test button, and its API refuses every AD
  CS operation.
- **Issued certificates replicate like any other certificate**, keys
  through the same need-to-know path; see `docs/cluster.md`.
- **Upgrade followers first, the control plane last.** v1.10.0 adds
  database migrations and certificate fields that a follower on an
  older release cannot read; this is the order `docs/cluster.md`
  ("Running a Mixed-Version Fleet") already prescribes.

## Supported templates

v1.10.0 supports templates that **issue immediately**. A template that
requires CA certificate manager approval answers *pending*: Lorica
stores nothing, discards the generated key, shows and audits the
authority's request identifier, and raises `cert_issuance_failed`.
Lorica never retrieves a pending request. Ask the authority's
administrators to deny it: if it were approved, the result would be a
valid certificate whose key no longer exists anywhere, which should then
be revoked. Remove the approval requirement from the dedicated template
instead.

## Export and import

- The authority is **not exported** with the configuration, like DNS
  provider credentials.
- Importing an AD CS certificate whose authority is not the one on the
  target node imports it as **manual**, with a warning. The response of
  `POST /api/v1/config/import` now carries a `warnings` list, and each
  warning is also logged.

## Side effects worth knowing

- **Every certificate event rotates the bot-protection secret.** An AD
  CS issuance or renewal, like an ACME one or an upload, rotates the
  bot-protection HMAC, which invalidates every visitor's verdict cookie:
  visitors on routes with bot protection solve the challenge again.
- **Unbound AD CS certificates are neither renewed nor purged.** The
  loop only renews certificates a route uses, and the cleanup of
  superseded unbound certificates only applies to ACME certificates. An
  AD CS certificate issued from the certificate page and never bound, or
  left behind by a cancelled route, stays on the certificate page until
  you bind or delete it; remember that deleting it does not revoke it.
- **Certificate export** applies to AD CS certificates as to any other:
  when it is enabled, an issuance or renewal writes the PEM files.

## Troubleshooting

The connection test and every failed issuance name the step that
failed. The dashboard shows the step's closed name and the client's
message; the message carries the detail.

### By failing step

| Step | Meaning | Look at |
|---|---|---|
| `kdc_discovery` | No KDC of the realm could be found or reached | DNS SRV records `_kerberos._tcp.corp.example.org`, the KDC list, the realm's spelling, flows to TCP/UDP 88 |
| `ticket_acquisition` | The KDC answered and refused, or the exchange failed | The KDC code (next table). Without a code: clock skew, an unknown principal, an unsupported encryption type |
| `tls` | The TLS connection to the endpoint failed | The endpoint CA bundle, or the system trust store, against the CES site's certificate; the host name in the URL against the certificate's names; flows to the CES host |
| `channel_binding` | The binding could not be computed from the endpoint's certificate | The message names the signature algorithm: RSASSA-PSS with parameters Lorica cannot read, or an unknown algorithm. Reissue the CES site certificate with RSA PKCS#1 v1.5 or ECDSA |
| `spnego` | The endpoint does not offer Negotiate, refused the token, or no service ticket was issued | CES in Kerberos mode and Windows Authentication enabled; the `HTTP/pki.corp.example.org` SPN registered once, on the pool identity; AES on the pool identity |
| `mutual_authentication` | The endpoint did not prove it holds the service key | A load balancer or proxy terminating the authentication in front of CES; a duplicate SPN on another account |
| `http` | An HTTP leg failed below the authentication: unexpected status, unreadable body, connection reset | The endpoint path, IIS logs |
| `soap` | The answer is not a WS-Trust response or fault Lorica can read | The endpoint path points at CES and not at another service |
| `chain` | The issued chain could not be built to the leaf | The CA's chain as returned; report it |
| `fault_permission` | CA fault `0x80094012` | Enroll permission (next table) |
| `fault_template` | CA fault `0x80094800` or `0x80094802` | Template name and publication (next table) |
| `fault_other` | Any other CA fault | The message carries the CA's text and code |
| `san_coverage` | The issued certificate does not cover the requested names | The template must use *Supply in the request*; the issued certificate was not stored and must be revoked at the authority |
| `certificate` | The issued certificate cannot be served with the generated key | Report it |
| `timeout` | The operation passed its bound | Silent KDCs or a slow CES; see [Timeouts](#timeouts-and-the-single-flight-guard) |
| `krb5_conf` | The generated `krb5.conf` could not be written | Permissions on `<data-dir>/adcs/` |
| `configuration`, `csr` | A parameter or the CSR was refused before anything was sent | The message names the field |

A denial (422 `adcs_denied`) is the CA refusing this request under its
policy; the message is the CA's.

### By KDC error code

The settings tab shows the code of a failed state with its meaning. For
the other codes the message carries MIT's text, which is what to search
for.

| Code | Name | Meaning | Opens the failed state |
|---|---|---|---|
| 24 | `KDC_ERR_PREAUTH_FAILED` | Wrong password ("Preauthentication failed") | Yes |
| 18 | `KDC_ERR_CLIENT_REVOKED` | Account disabled or locked out ("Client's credentials have been revoked") | Yes |
| 23 | `KDC_ERR_KEY_EXPIRED` | Password expired ("Password has expired") | Yes |
| 6 | `KDC_ERR_C_PRINCIPAL_UNKNOWN` | The principal does not exist in the realm: check its spelling and realm ("Client not found in Kerberos database") | No |
| 14 | `KDC_ERR_ETYPE_NOSUPP` | No common encryption type: enable AES on the account ("KDC has no support for encryption type") | No |
| 37 | `KRB_AP_ERR_SKEW` | Clock skew: synchronise the host's time ("Clock skew too great") | No |

### By CA error code

| Code | Name | Meaning |
|---|---|---|
| `0x80094012` | `CERTSRV_E_TEMPLATE_DENIED` | The service account has no *Enroll* permission on the template |
| `0x80094800` | `CERTSRV_E_UNSUPPORTED_CERT_TYPE` | The template is unknown to this CA: not published on it, or named by its display name instead of its common name |
| `0x80094802` | `CERTSRV_E_TEMPLATE_CONFLICT` | The template identifiers map to two different templates; ask the administrators |

## What Lorica refuses, and why

These are refused, not missing. There is no setting to enable them.

- **NTLM.** It is relayable, deprecated by Microsoft, and refused by
  hardened deployments. Kerberos with a channel binding is the only
  authentication mode, and the binding cannot be disabled.
- **HTTP Basic, and CES instances in *UsernamePassword* mode.** They
  send the password itself to the web server.
- **The web enrollment pages (`/certsrv`).** They are HTML forms meant
  for a person; an integration would parse pages that change with the
  server's version and language, and they are the target of ESC8.
- **The `san:` request attribute.** It only works on an authority with
  `EDITF_ATTRIBUTESUBJECTALTNAME2` set (ESC6); supporting it would
  reward a misconfiguration authorities are told to remove. Names travel
  in the CSR's SAN extension, which *Supply in the request* honours.
- **Wildcard names.** Refused in this release, whatever the allowlist.
- **Key reuse across renewals.** Every issuance and renewal gets a new
  key.
- **Issuance and renewal from the automation plane or MCP.** Issuing
  from a domain-wide authority stays a human decision on the management
  plane; tokens cannot issue, and are refused on renewal with
  `adcs_renewal_not_on_automation_plane`.
- **An ACME gateway in front of AD CS.** The client is inside Lorica,
  with no extra service to operate.

Not in this release, and possible later:

- **Keytab credentials.** A keytab needs a domain administrator to run
  `ktpass`, and silently stops working when the account's password
  changes. The password is the only credential in v1.10.0.
- **Several authorities.** One per installation; certificates already
  reference their authority, so more can be added later without a data
  migration.
- **Templates that need approval**, see
  [Supported templates](#supported-templates).

## Cross-realm

An account in a child domain reaching an authority in its parent
domain was observed to work against Active Directory during the design
spike: MIT Kerberos followed the AD KDC's cross-realm referral with no
configuration beyond DNS SRV discovery. It is **not covered by the
end-to-end test profile**, whose single MIT realm does not reproduce an
AD KDC's referral, so treat it as observed, not tested.

If the service account and the CES host are in different realms, leave
the KDC list empty: with an explicit list, the generated `krb5.conf`
turns DNS discovery off and names KDCs for the service account's realm
only, so the other realm's KDCs cannot be located.

## API reference

| Method and path | Role | What it does |
|---|---|---|
| `GET /api/v1/adcs/authority` | Viewer | The authority without its password (`password_set`), with its failed state; `managed_on_control_plane` on a follower |
| `PUT /api/v1/adcs/authority` | SuperAdmin | Create or update; `password` required on creation and on an identity change |
| `DELETE /api/v1/adcs/authority` | SuperAdmin | Refused while certificates reference it |
| `POST /api/v1/adcs/authority/test` | Operator | The connection test |
| `POST /api/v1/certificates/adcs` | Operator | Issue a certificate: an issuance at the authority |
| `POST /api/v1/certificates/{id}/renew` | Operator | "Renew now", for an AD CS certificate as for an ACME one |
| `GET /api/v1/adcs/adoption-candidates` | Viewer | Manual certificates the issuing CA signed |
| `POST /api/v1/certificates/{id}/adcs/adopt` | Operator | Adopt one certificate |
| `POST /api/v1/certificates/{id}/adcs/revert` | Operator | Revert to manual |

On a follower, the authority read answers `managed_on_control_plane`
and every operation is refused. `lorica-api/openapi.yaml` has the
request and response shapes. The alert types are
`adcs_authority_failed` and `cert_issuance_failed`; channels saved with
an explicit alert list are subscribed to both on upgrade.
