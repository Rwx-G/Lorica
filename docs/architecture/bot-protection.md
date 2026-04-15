# Bot protection architecture

Author: Romain G.
Status: Design — implementation lands across v1.4.0 Epic 3
(stories 3.2 through 3.10).

This document specifies Lorica's self-hosted bot-protection stack:
three graded challenge modes (Cookie, JavaScript proof-of-work,
image captcha), an HMAC-signed verdict cookie, a five-category
bypass matrix, and an inverse-country gate. The design avoids any
third-party dependency — no Cloudflare Turnstile, no reCAPTCHA, no
hCaptcha, no remote scoring API. Every verdict is computed inside
Lorica.

The target audience is (a) contributors implementing Epic 3 stories
and (b) operators who need to reason about why a legitimate client
is blocked or a known-bad actor is let through. Threat-model
exclusions are documented in § 10.

---

## 1. Goals

1. **Zero third-party dependency.** The entire challenge is rendered
   from a single HTML response served by Lorica. No cross-origin
   script, no remote token endpoint, no telemetry beacon. Air-gapped
   deployments must work unchanged.
2. **Graded intrusion model.** The operator picks the friction
   level per route: Cookie (passive, zero UX cost), JavaScript PoW
   (transparent ~50 ms to ~2 s pause), Captcha (explicit user
   interaction). BunkerWeb-style escalation path when a lower tier
   stops filtering the traffic the operator cares about.
3. **Stateless verdict.** Once a client solves the challenge, the
   verdict is carried in an HMAC-signed cookie bound to
   `(route_id, client IP prefix, expires_at)`. No per-session row
   in SQLite. A restart drops the cookie-verifying secret only on
   cert renewal (see § 7), which is a bounded and documented
   behaviour.
4. **Worker parity.** A challenge solved on one worker must be
   honoured on every other worker in the pool. Reuses the
   `VerdictCacheEngine::Rpc` plumbing that shipped in v1.3.0
   for forward-auth (WPAR-2); no new RPC endpoint.
5. **Bounded hot-path cost.** A request carrying a valid cookie
   pays exactly one HMAC verify (≈ 1 µs on commodity hardware). A
   request without a cookie pays the challenge render (once per
   NAT gateway worth of clients, caching skipped by design — see
   § 3.1) or the bypass-list scan if any bypass is configured.

## 2. Non-goals

- **Block dedicated adversaries.** A determined attacker with a
  headless-Chrome farm and real-browser fingerprints defeats JS
  PoW, and a low-wage CAPTCHA-farm defeats the image challenge.
  This stack targets automated crawlers, vulnerability scanners,
  and casual credential-stuffing scripts — not nation-states or
  funded adversaries.
- **Replace WAF or rate-limiting.** Bot protection sits on top of
  the existing defences. A request that passes the challenge still
  goes through WAF, rate limits, IP blocklist, GeoIP.
- **Prove human presence.** Captcha is a weak human-presence
  signal at best; the design assumes it catches noise, not motivated
  traffic.
- **Distributed challenge state.** Verdicts are shared across
  workers within one Lorica process, NOT across Lorica nodes. A
  client solving the challenge on node A still gets prompted on
  node B. Operators deploying multi-node Lorica should either
  front with a sticky-session load balancer or accept the
  double-challenge tradeoff.

## 3. Challenge modes

### 3.1 Cookie (passive)

Renders a minimal HTML page with a `<meta http-equiv="refresh">`
that bounces the browser back to the original URL carrying a
freshly-minted verdict cookie. This is *not* a CAPTCHA — any
browser that executes the refresh passes, scripts that follow
redirects without cookie jar handling do not.

Useful as a first tier against `wget`, `curl`, and unsophisticated
HTTP scanners that don't persist cookies.

**Cost:** one extra round trip per new visitor. **Bypass:** any
HTTP library that handles cookies + redirects (Python
`requests.Session`, Go `http.Client{Jar: ...}`, …), so escalate to
mode 2 or 3 when the attacker is non-trivial.

### 3.2 JavaScript proof-of-work

Renders an HTML page with an inline `<script>` that runs SHA-256
over `{challenge_nonce || counter}` until the hash has N leading
zero bits (N configurable 14–22). The counter that satisfies the
target is POSTed back; Lorica verifies in ~1 µs and sets the
verdict cookie.

**Algorithm:** SHA-256 — the browser's `crypto.subtle.digest` is
faster than any pure-JS implementation and works offline. No
external fetch from the challenge page.

**Difficulty scale** (approx, tuned on 2024 mid-range laptop):

| N bits | median solve time | use case |
|---|---|---|
| 14 | ~50 ms | "catch the obvious crawlers" |
| 16 | ~200 ms | default-but-tighter |
| 18 | ~800 ms | **default** (balance UX vs. bot cost) |
| 20 | ~3 s | operator under active scanning pressure |
| 22 | ~12 s | emergency; UX degraded for mobile |

Each additional bit doubles expected solve time. An attacker
running headless Chrome pays the same CPU budget as a real
browser — the cost asymmetry favours the defender when the
attacker operates at scale.

**Cost:** one extra round trip + N-dependent CPU on the client.
**Bypass:** headless Chrome, Playwright, Selenium with a JS
engine. The mitigation is the graded model: escalate to mode 3.

### 3.3 Image captcha

Renders an HTML page with an `<img>` pointing at a one-shot URL
signed with the challenge nonce. The server generates a 6-character
code from the captcha alphabet (see § 4.3), renders a PNG via the
pure-Rust `captcha` crate (version pinned in `lorica-challenge`'s
Cargo.toml, ~2 KiB per image), and caches the expected solution in
a short-lived verdict stash keyed by the signed URL. The user
types the code; server verifies and sets the verdict cookie.

**Cost:** one extra round trip + human reading time. **Bypass:**
paid CAPTCHA-solving services (~$1 per 1000 solves). The
mitigation is that the friction is now measured in human hours —
economics of automated abuse change shape.

## 4. Verdict cookie format

### 4.1 Structure

```
lorica_bot_verdict = base64url(payload || hmac_sig)

payload = route_id (16 bytes UUID)
       || client_ip_prefix (4 bytes for v4 /24, 8 bytes for v6 /64)
       || expires_at_epoch_seconds (4 bytes, little-endian u32)
       || mode (1 byte: 1=Cookie, 2=Javascript, 3=Captcha)

hmac_sig = HMAC-SHA256(secret, payload) truncated to 16 bytes
```

Total size: 41 bytes (v4 client) or 45 bytes (v6). Base64url
encoded: ~60 bytes, fits in any reasonable `Set-Cookie` header.

### 4.2 IP prefix binding

The HMAC includes a **prefix** of the client IP — `/24` for IPv4
and `/64` for IPv6 — rather than the full address. Rationale:

- **NAT tolerance.** A home router rotates the outbound port (and
  occasionally the address) between requests from the same
  client. A corporate NAT often has a pool of outbound IPs. A
  strict full-address binding would invalidate the cookie mid-
  session.
- **Replay scope cap.** A cookie stolen from one client is only
  replayable by another client behind the same NAT gateway. /24
  covers a typical residential NAT (or a small corporate site);
  /64 matches the IPv6 per-customer allocation most ISPs hand
  out (the "one subnet per subscriber" convention).

Tradeoff: an attacker on the same /24 as the victim (shared-wifi
at a conference, hotel network, small ISP CGNAT) can reuse the
cookie. This is documented as a deliberate choice; operators
needing tighter binding can bring a route-level
`verdict_cookie_ip_prefix_v4 = 32` override in a future version.

### 4.3 Expiry

Cookie expiry ships from the `cookie_ttl_s` per-route setting
(default **86400 s = 24 h**, capped at 604800 s = 7 days by the
API validator). Verifier rejects any cookie whose
`expires_at < now`. Clock skew: ± 30 s grace is applied at verify
time to tolerate drift between Lorica and the client browser.

### 4.4 HMAC secret

A 32-byte random secret, generated once at first boot and stored
in the SQLite config DB under `global_settings.bot_hmac_secret`.
Rotated **on every certificate renewal** (so the secret lifetime is
capped at ≤ cert_ttl, typically 90 days for ACME Let's Encrypt, 1
year for manual certs). Rotation invalidates all outstanding
verdict cookies — an acceptable UX cost given the rotation cadence.

Mechanism: the ACME renewal path (`src/acme/*`) and the manual cert
upload path both call `lorica_challenge::rotate_hmac_secret()`
after the new cert lands. Rotation is atomic (ArcSwap of the
resolved secret bytes); in-flight requests on the old secret
complete with their old cookie valid until expiry.

Failure mode: if rotation fails (SQLite write error), the old
secret stays live. Logged at `warn!`. The next cert renewal
re-attempts rotation.

## 5. Proof-of-work verification

### 5.1 Wire format

```
Challenge (server → client), embedded as JS vars:
  nonce      = 16 bytes random, hex-encoded
  difficulty = N (u8 in 14..=22)
  expires_at = epoch seconds, u64

Solution (client → server) POSTed as form-urlencoded:
  nonce    = <same as challenge>
  counter  = <u64 as decimal string>
```

### 5.2 Verify path

```
1. Parse (nonce, counter) from request body. Reject on bad shape.
2. Check expires_at > now. Reject if expired.
3. Compute h = SHA256(nonce_bytes || counter_bytes).
4. Check first N bits of h are zero. Reject otherwise.
5. Issue verdict cookie.
```

Step 3 is ~500 ns per verify on a 2024 x86 server. Step 4 is
free (bit comparison).

### 5.3 Replay protection

The challenge nonce is bound inside the verdict cookie's HMAC so
the same nonce cannot be used to mint a second cookie for a
different `(route_id, client_ip_prefix)` combination. Using the
same nonce for the same target is cheap (the attacker already
solved it once) and is a non-issue: the resulting cookie has the
same scope as the first one.

### 5.4 DoS resistance

Challenge generation is O(nonce_write + secret_hmac), roughly 1
µs per render. The verify path is O(1). A 10-Gbit link at the
smallest rendered challenge page (~1.5 KiB) maxes out at ~800k
renders/s, which is below the typical Lorica CPU budget for any
other request handler. No additional rate-limit is applied on the
challenge render itself — the existing per-route rate limit in
`lorica::proxy_wiring::RateLimitEngine` covers it.

## 6. Bypass matrix

Five bypass categories, evaluated in strict order. First match
wins and skips the challenge entirely:

| # | Category | Match criterion | Typical use |
|---|---|---|---|
| 1 | `ip_cidrs` | Client IP ∈ one of the CIDRs | office subnet, monitoring probe |
| 2 | `asns` | rDNS → IP → ASN lookup matches | trust "all of Googlebot's ASN" without listing every IP |
| 3 | `countries` | GeoIP resolved country ∈ list | internal-only service scoped to 1 country |
| 4 | `user_agents` | Regex match on `User-Agent` header | allowlist `Mozilla/5.0 (compatible; Googlebot/.*)` with rDNS forward-confirmation as a separate belt-and-braces check |
| 5 | `rdns` | PTR record suffix matches | `googlebot.com`, `search.msn.com` — the canonical crawler identity signal |

### 6.1 rDNS spoofing defence

Categories 4 and 5 optionally pair with a **forward-confirmation**
check: after the PTR lookup, do a forward A / AAAA lookup on the
PTR result and verify it resolves back to the same client IP.
Without forward confirmation, a hostile resolver can point any
PTR at `crawl.google.com` and bypass the challenge. This is the
same guard that every respectable crawler-allowlisting
implementation uses.

Cache TTL for the rDNS + forward confirm is 1 h, keyed by client
IP. A bounded LRU (16k entries) caps memory. On cache miss the
challenge is shown (fail-closed) rather than the rDNS being
resolved inline — a DNS-slow query must not block the hot path.
The cache is populated asynchronously on the FIRST match attempt
for a given IP so subsequent requests from the same IP get the
fast path.

### 6.2 `only_country` inverse filter

When `only_country` is set (non-empty list of ISO alpha-2 codes),
the challenge fires **only** when the resolved country is in the
list. Intended for operators who want to protect a service mostly
used domestically: enable JS PoW only for traffic from known
bot-farm jurisdictions, and let everyone else through with zero
friction.

`only_country` is evaluated AFTER the bypass rules — so an IP in
`ip_cidrs` bypasses regardless of country, but a foreign IP that
is not in any bypass still gets the challenge only if
`only_country` matches.

### 6.3 Precedence summary

```
bypass_ip_cidrs     → skip challenge
bypass_asns         → skip
bypass_countries    → skip
bypass_user_agents  → skip (with optional rDNS forward confirm)
bypass_rdns         → skip (with forward confirm)
only_country set && country ∉ list → skip (challenge only for listed countries)
valid verdict cookie → pass through
otherwise → render challenge page
```

## 7. HMAC secret lifecycle

1. **First boot.** `bot_hmac_secret` key is missing from
   `global_settings`. `lorica_challenge::init_secret` generates 32
   bytes from `getrandom`, writes them to SQLite, loads into the
   process-wide `ArcSwap<[u8; 32]>`.
2. **Reload path.** `lorica::reload::apply_bot_secret_from_store`
   reads the current secret from SQLite and publishes it. Runs
   inside `reload_proxy_config_with_mtls` alongside
   `apply_otel_settings_from_store` and
   `apply_geoip_settings_from_store`. Dedups via the usual
   snapshot-and-compare pattern.
3. **Rotation.** ACME renewal and manual cert upload both call
   `lorica_challenge::rotate_hmac_secret`. Writes a new 32-byte
   random secret, triggers a reload, and logs at `info!`. Old
   cookies stop verifying immediately — users re-solve on their
   next request. Given typical ACME cadence (≤ 90 days) and the
   default 24-h cookie TTL, the operator-visible consequence is
   one "please solve again" prompt per renewal cycle, which is
   invisible in practice.
4. **Failure modes.** SQLite write failure → old secret stays
   live, `warn!` fires, next renewal retries. getrandom failure
   → fatal at first boot (cannot serve challenges without a
   secret); never fatal at rotation time (old secret continues).

## 8. Request-filter placement

```
connection filter (pre-route)
       │
       ▼
route match
       │
       ▼
IP ban + IP blocklist
       │
       ▼
per-route rate limit
       │
       ▼
mTLS
       │
       ▼
GeoIP country filter
       │
       ▼
BOT PROTECTION  ← this epic (before forward_auth, after GeoIP)
       │
       ▼
forward_auth
       │
       ▼
WAF evaluation
       │
       ▼
upstream
```

Rationale for the position:

- **After GeoIP.** The `bypass.countries` and `only_country`
  filters depend on the resolved country, which is computed in
  the GeoIP stage. Swapping the order would force a second GeoIP
  lookup or couple the two stages.
- **Before forward_auth.** Bot protection is cheaper than a
  forward_auth HTTP round trip to an external IdP, so failing
  closed on bots earlier saves the IdP's SLA budget and masks
  automated probing from the IdP's audit logs.
- **Before WAF.** Same reasoning: WAF regex evaluation is the
  most expensive stage (microseconds per rule × rule count), and
  a bot that cannot solve the challenge never reaches it.

## 9. Metrics + OTel

**Prometheus counter:**
`lorica_bot_challenge_total{route_id, mode, outcome}`

`outcome` ∈ { `shown` (first time, no cookie), `passed` (valid
cookie), `failed` (bad solution / expired cookie / HMAC mismatch),
`bypassed` (one of the 5 bypass categories matched) }.

Cardinality: routes × 3 modes × 4 outcomes = bounded, well inside
Prometheus comfort.

**OTel span attribute:** `bot_protection.challenge` on the root
`http_request` span, populated with `mode`, `outcome`, and
`bypass_reason` (category name, when applicable). No separate
child span — the challenge is evaluated inside request_filter
which is already inside the root span.

## 10. Threat model

### 10.1 In scope

- **Stops:** unsophisticated crawlers, curl / wget scripts, nmap
  HTTP probes, headless scanners that don't run JS or handle
  cookies, and low-resource credential-stuffing scripts.
- **Raises cost for:** mid-tier bot operators who run on rented
  VPS pools — each IP must now solve the challenge once per 24 h
  per route, which breaks fire-and-forget abuse economics.

### 10.2 Out of scope

- **Headless Chrome / Playwright farms.** Solve JS PoW natively.
  Mitigation: escalate to captcha, accept the UX cost.
- **CAPTCHA-solving services.** Solve image captchas at ~$1 /
  1000. Mitigation: none inside Lorica — the operator's recourse
  is to pair with an external reputation feed (not part of this
  epic).
- **Sophisticated cookie theft.** An attacker with XSS or a
  network-level MITM can capture the verdict cookie. The IP
  prefix binding limits replay to the same NAT gateway but does
  not prevent the attack outright. Mitigations exist elsewhere
  in the stack (CSP, HSTS, secure-cookie flag — all emitted by
  Lorica's default security headers).
- **Same-NAT adversarial neighbours.** A hostile client on the
  same `/24` (v4) or `/64` (v6) can replay the victim's cookie.
  Covered in § 4.2 as a deliberate NAT-tolerance tradeoff.
- **Protocol downgrade.** An attacker that forces the challenge
  response down to plaintext HTTP/1.0 and strips the Set-Cookie
  header. Mitigation: the deployment should front Lorica with
  TLS (the default Lorica posture) so HTTP downgrade requires
  active MITM.

### 10.3 Bypass matrix risk

Each bypass category is a potential vector:

- **`ip_cidrs`:** trivially correct — the client IP either is or
  is not in the CIDR. Risk is operator misconfiguration
  (bypassing `0.0.0.0/0`).
- **`asns`:** depends on the ASN database freshness. Using a
  stale snapshot leaves a window where a recently-transferred
  block is mis-attributed. Kept low-severity because ASN
  transfers are rare (~weekly at the RIR level).
- **`countries`:** relies on GeoIP. Same assumptions as GeoIP
  filtering — see the GeoIP doc for DB freshness tradeoffs.
- **`user_agents`:** trivially spoofable by a bad actor. Only
  useful with forward-confirm rDNS pairing, which is why the
  dashboard UI surfaces the two as "pair for safety".
- **`rdns`:** the forward-confirmation step is the reason this
  is safe. Without it, any PTR can lie. The implementation
  MUST enforce forward confirm before treating an rDNS match as
  a bypass; this is a must-not regression in the test suite.

## 11. Implementation checklist

The stories below map one-to-one to the ROADMAP entries for
v1.4.0 Epic 3. This section is the definition-of-done contract —
an implementation is not complete until every checkbox below is
ticked.

- [ ] **3.2** `lorica-challenge` crate: `generate_pow_challenge`,
      `verify_pow`, `generate_captcha_image`, cookie sign / verify
      (constant-time), `rotate_hmac_secret`. Unit tests at each
      public boundary. No `unwrap` on user-reachable paths.
- [ ] **3.3** `Route.bot_protection: Option<BotProtectionConfig>`
      in `lorica-config`, schema migration V36, API validation
      (mode enum, difficulty range 14..=22, alphabet non-empty
      and ASCII-printable, countries ISO alpha-2, CIDR well-
      formed, regex compiles).
- [ ] **3.4** Inline HTML challenge pages. No external asset.
      `<noscript>` block with operator-contact hint. Plain-text
      fallback for non-HTML clients (`Accept:` without
      `text/html`).
- [ ] **3.5** `request_filter` evaluates bypass in the exact
      order specified in § 6.3, emits the right metric labels,
      issues / verifies the cookie, and routes the POSTed
      solution to the verifier. rDNS bypass enforces forward
      confirmation.
- [ ] **3.6** Verdict cache wired through
      `VerdictCacheEngine::Rpc` in worker mode; single-process
      uses the existing in-process cache. Key format as
      specified.
- [ ] **3.7** Prometheus counter + OTel span attribute, both
      with bounded cardinality.
- [ ] **3.8** Dashboard Bot Protection tab under Protection,
      with mode dropdown, difficulty slider, alphabet editor,
      five-category bypass editor, `only_country` multi-select.
- [ ] **3.9** E2E tests covering: cookie passthrough, PoW
      solve-and-verify, captcha image + verify, all five bypass
      categories, `only_country` gate, HMAC rotation.
- [ ] **3.10** TESTING-GUIDE section with a minute-and-a-half
      walkthrough per mode.

---

## 12. Open questions

- **Per-route vs. global HMAC secret.** Current design uses a
  single global secret. A per-route secret would scope a secret
  compromise to one route, at the cost of N secrets to rotate.
  Deferred: rotation is already rare and a global secret is
  simpler to reason about. Revisit if a future security finding
  pushes for scope isolation.
- **Stale-while-revalidate on rDNS cache.** A stale PTR match
  could serve one request after its real TTL expired. Current
  design fail-closes on cache miss (shows the challenge). The
  alternative — stale-while-revalidate with a 5 min grace — is
  deferred pending real-world data on rDNS lookup latency.
- **JS PoW worker threads.** A naive in-page solver blocks the
  main thread for large N. Using a Web Worker would let the page
  remain responsive but adds bundle size (~4 KiB compiled JS).
  Tracked as a UX follow-up, not a security one.
