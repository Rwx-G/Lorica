# AI / LLM crawler deny-list

Story 8.2 ships first-class deny-list support for AI / LLM training
crawlers (GPTBot, ClaudeBot, CCBot, PerplexityBot, ...). This page
documents the operator-facing surface : the built-in registry, the
custom-crawler workflow, the per-route policy, and the verification
flows.

## Built-in registry

Lorica ships 16 curated crawler entries sourced from the
community-maintained `ai-robots-txt/ai.robots.txt` snapshot
(2026-05-03), each tagged with a verification mechanism :

| Crawler | Verification | Source |
|---|---|---|
| GPTBot | `IpRanges` | https://openai.com/gptbot.json |
| ChatGPT-User | `IpRanges` | https://openai.com/chatgpt-user.json |
| OAI-SearchBot | `IpRanges` | https://openai.com/searchbot.json |
| ClaudeBot | `IpRanges` | https://claude.com/crawling/bots.json |
| Claude-User | `IpRanges` | (same Anthropic JSON) |
| Claude-SearchBot | `IpRanges` | (same Anthropic JSON) |
| anthropic-ai | `IpRanges` | (same Anthropic JSON ; legacy alias) |
| CCBot | `Rdns` (`.crawl.commoncrawl.org`) | https://commoncrawl.org/ccbot |
| PerplexityBot | `IpRanges` | https://www.perplexity.ai/perplexitybot.json |
| Perplexity-User | `IpRanges` | https://www.perplexity.ai/perplexity-user.json |
| Bytespider | `UaOnly` | (no published verification) |
| Google-Extended | `UaOnly` | robots.txt-only opt-out token |
| Applebot / Applebot-Extended | `Rdns` (`.applebot.apple.com`) | https://support.apple.com/en-us/119829 |
| Amazonbot | `IpRanges` | https://developer.amazon.com/amazonbot |
| FacebookBot / facebookexternalhit / Meta-ExternalAgent | `IpRanges` | AS32934 (BGP table) |
| Diffbot | `UaOnly` | (no public verification) |

Vendor IP-list JSONs ship at `lorica/src/ai_bot/vendor_ips/` paired
with sibling `.sha256` integrity pins and `.source` provenance
files. SHA-256 mismatch at startup degrades that vendor's range
set to empty (worker never panics) ; the empty set falls through
the spoofed-fallback flow.

## Verification kinds

Three mechanisms drive the per-crawler dispatch :

- **Rdns** - Forward-confirmed reverse-DNS via `bot_rdns`. The
  cache-only hot path stays sub-millisecond ; cache misses
  fire-and-forget a resolve so the next request from the same IP
  lands on a hit. Strongest verification (cryptographic), available
  for ~2 vendors.
- **IpRanges** - Vendor-published CIDR list bundled at compile
  time. O(N) linear scan against the bundled `Vec<IpNet>`. Refresh
  cadence : alongside each Lorica patch release. Available for ~8
  vendors. The IP MUST be the post-trust-boundary peer IP from
  `RequestCtx.client_ip` ; reading the raw `X-Forwarded-For` header
  here would let a malicious client claim to be in any vendor's
  CIDR by spoofing XFF.
- **UaOnly** - User-Agent string match alone. Trivially spoofable.
  The `lorica_ai_bot_total{action="ua_only_match"}` counter
  surfaces hits for operator visibility ; spoofed-fallback does
  NOT apply (no spoof signal possible).

## Per-route policy (AC #2)

Three values for `Route.ai_bot_policy` :

- **Off** (default) - filter is a no-op. Pre-Story-8.2 behaviour.
- **Deny** - 403 + `Retry-After: 86400` + the route's
  `error_page_html` (if set, else a hardcoded plain-text fallback).
- **Log** - allow + counter increment + structured-log entry. Use
  this to size up bot traffic before flipping to `Deny`.

## Spoofed-fallback (AC #3)

When a crawler's verification fails (rDNS suffix mismatch / IP
outside vendor CIDR list), Lorica applies a fallback :

- Per-route override : `Route.ai_bot_spoofed_fallback`. `None`
  defers to the global setting.
- Global default : `GlobalSettings.ai_bot_treat_spoofed_as`,
  default `Deny`.

Three values :

- **Deny** - reject with the same 403 / `Retry-After` shape as the
  matched-crawler Deny path. Default global value.
- **Log** - allow + `lorica_ai_bot_total{action="spoofed"}`.
- **Allow** - allow silently (no Decision, no spoofed counter).

## False-positive policy

Googlebot AND Bingbot are intentionally **excluded** from the
built-in registry. They are search-index bots, not LLM training
crawlers ; blocking them by accident is a real operator risk
(SEO impact). Google has a separate `Google-Extended` opt-out
token for AI training - in the registry as `UaOnly` (robots.txt
token only, not a distinct fetcher). Microsoft has not published a
separate AI-training opt-out for Bingbot as of 2026-05-03.

Operators wanting to block search engines (rare) use Custom
Crawlers explicitly.

## Custom crawlers (AC #6)

Operators can define their own crawler entries via the API or the
Settings -> AI crawler registry -> Custom crawlers panel.

Schema (POST body) :

```json
{
  "name": "MyCustomBot",
  "user_agent_pattern": "(?i)\\bMyCustomBot\\b",
  "verification": { "kind": "ip_ranges", "cidrs": ["203.0.113.0/24"] },
  "enabled": true
}
```

Server-side validation pipeline :

- Regex compiles via `RegexBuilder::size_limit(1<<20).dfa_size_limit(1<<21).case_insensitive(true)`. Bad regex -> HTTP 400.
- Compiled regex matched against a 20-entry baseline UA corpus
  (Chrome / Firefox / Safari / Edge / Opera + curl + wget + 7
  search-bot UAs + facebookexternalhit) ; any baseline match -> HTTP 400.
  This closes the admin `(?i).*` / `Mozilla` privilege-escalation
  path.
- For `kind=ip_ranges` : each CIDR parses via `ipnet::IpNet::from_str` ; first invalid -> HTTP 400 ; `cidrs.len() <= 64`.
- For `kind=rdns` : `suffixes` non-empty, each entry starts with `.`.
- POST : total row count < 256.

On conflict by `name` (custom matches a built-in), **custom wins**.
This lets operators override a stale built-in IP list mid-cycle
when a vendor changes their published JSON before the next Lorica
patch release.

## `/robots.txt` auto-generation (AC #10)

Per-route opt-in via `Route.serve_robots_txt = true`. Default
`false` preserves backward compat (existing deployments keep
passthrough to backend).

When ON, Lorica intercepts GET `/robots.txt` for the route and
serves a registry-driven body :

```
# Generated by Lorica vX.Y.Z
# Source: ai-robots-txt/ai.robots.txt @ snapshot 2026-05-03

User-agent: GPTBot
Disallow: /

User-agent: ClaudeBot
Disallow: /
...
```

When `ai_bot_policy = Off` on the route, the body falls back to
`User-agent: *\nAllow: /\n` (no crawlers active = nothing to opt
out of). Response headers : `Content-Type: text/plain; charset=utf-8`,
`Cache-Control: public, max-age=3600`.

robots.txt is advisory only - it does NOT replace the
policy enforcement from AC #2/3 ; it complements it for crawlers
that respect robots.txt (Cloudflare's Verified Bots program reports
~40% AI-crawler compliance as of 2025, so the dual-layer approach
matters).

## Verified-bot header injection (AC #11)

When a crawler's verification confirms (`Rdns` matched / `IpRanges`
in-range / `UaOnly` matched), Lorica injects two headers into the
upstream request before forwarding :

- `X-Lorica-Verified-Bot: <crawler.name>` (only on Rdns / IpRanges
  ; UaOnly skips this header to distinguish trust levels).
- `X-Lorica-Bot-Verification: rdns | ip_ranges | ua_only`.

Backends consume these for rate-limit differential, audit-log
enrichment, bot-only response caches. The injection uses
`insert_header` (overwrite, not append) so a client-supplied
`X-Lorica-Verified-Bot: GPTBot` cannot launder its way upstream
(trust-laundering defense).

Gated by global `GlobalSettings.ai_bot_inject_headers` (default
`true`).

## Operator workflows

### Block all built-in AI crawlers on a route

```
PUT /api/v1/routes/{id}
{ "ai_bot_policy": "deny" }
```

### Log-only mode (size up traffic before deny)

```
PUT /api/v1/routes/{id}
{ "ai_bot_policy": "log" }
```

### Override a stale vendor IP list mid-cycle

A vendor publishes a fresh CIDR list before the next Lorica patch
release. Two paths :

1. Wait for the next Lorica patch release (vendor JSONs refresh
   alongside Lorica releases - typically ~monthly).
2. Immediate workaround via Custom Crawlers : disable the stale
   built-in entry (POST a Custom Crawler with the same `name` and
   `enabled: false`), then add a fresh entry with the new CIDR
   list. The merged registry's custom-wins-on-conflict semantics
   takes care of the rest.

### Add a new vendor not yet in the built-in registry

Custom Crawler CRUD via `POST /api/v1/ai-crawlers/custom` (admin
auth in v1.6.0 ; Story 8.3 will retag to Operator + SuperAdmin).
Pick verification kind based on what the vendor publishes :

- rDNS suffix -> `kind: rdns` with `suffixes`.
- IP-list JSON URL -> `kind: ip_ranges` with `cidrs` prefetched.
- Neither -> `kind: ua_only`.

## Troubleshooting

```
# Is request X classified as an AI bot ?
curl -s -H "Cookie: <session>" \
  'https://localhost:9443/api/v1/ai-crawlers/test?ua=GPTBot/1.0&route_id=42'

# What does the auto-served /robots.txt look like for route Y ?
curl -s -H "Cookie: <session>" \
  'https://localhost:9443/api/v1/ai-crawlers/robots-preview?route_id=42'

# How many AI-bot hits in the last 5 minutes (per-route, per-action) ?
curl -s -H "Cookie: <session>" \
  'https://localhost:9443/api/v1/ai-crawlers/stats?route_id=42&window=5m'
```

The `/test`, `/robots-preview`, and `/stats` endpoints are
follow-ups to the v1.6.0 base CRUD release ; for the long-range
view, scrape `/metrics` for `lorica_ai_bot_total` into Prometheus.

## Operator tunables

- Globals : `ai_bot_treat_spoofed_as` (default `Deny`),
  `ai_bot_inject_headers` (default `true`).
- Per-route : `ai_bot_policy` (default `Off`),
  `ai_bot_spoofed_fallback` (default `None` = inherit global),
  `serve_robots_txt` (default `false`).

## Out of scope (deferred)

- **Vendor IP-list runtime refresh daemon** (proposed Story 8.13,
  v1.7.0+) - v1.6.0 bundles vendor JSONs at compile time.
- **RBAC tagging** (Story 8.3) - v1.6.0 ships single-admin auth
  for the custom CRUD endpoints.
- **Audit-log integration** (Story 8.9) - v1.6.0 does not emit
  `lorica::audit` events on AI-bot decisions.
- **Per-route bot category aggregation** (HAProxy Enterprise-style
  "block all training bots" UX) - deferred to v1.7.0+.

## Cross-references

- `docs/architecture/bot-protection.md` - the existing
  bot-challenge layer is orthogonal to the AI-bot deny layer.
- Story 8.2 spec : `docs/stories/story-8.2-ai-crawler-deny-list.md`.
