# Fork Information

Lorica is a fork of [Cloudflare Pingora](https://github.com/cloudflare/pingora), modified to serve as a dashboard-first reverse proxy product.

## Origin

| Field | Value |
|-------|-------|
| Upstream repository | <https://github.com/cloudflare/pingora> |
| Upstream license | Apache-2.0 |
| Fork date | 2026-03-29 |
| Upstream version at fork | `0.8.0` baseline (upstream `main` as of the fork date: after the `0.8.0` release of 2026-03-02, before `0.8.1`) |
| Git remote | `upstream` - `https://github.com/cloudflare/pingora.git` |

## Renaming Rules

All crate names and Rust module paths were renamed:

| Upstream name | Lorica name | Notes |
|---------------|-------------|-------|
| `pingora-core` | `lorica-core` | Core server framework |
| `pingora-proxy` | `lorica-proxy` | HTTP proxy engine |
| `pingora-http` | `lorica-http` | HTTP utilities |
| `pingora-error` | `lorica-error` | Error types |
| `pingora-pool` | `lorica-pool` | Connection pool |
| `pingora-timeout` | `lorica-timeout` | Timeout utilities |
| `pingora-header-serde` | `lorica-header-serde` | Header serialization |
| `pingora-runtime` | `lorica-runtime` | Tokio runtime wrapper |
| `pingora-ketama` | `lorica-ketama` | Consistent hashing |
| `pingora-limits` | `lorica-limits` | Rate estimator |
| `pingora-load-balancing` | `lorica-lb` | Load balancing strategies |
| `pingora-cache` | `lorica-cache` | HTTP response cache |
| `pingora-memory-cache` | `lorica-memory-cache` | In-memory cache backend |
| `pingora-lru` | `lorica-lru` | LRU eviction |
| `tinyufo` | `tinyufo` | TinyUFO cache algorithm (unchanged) |

**Rust imports**: all `use pingora_*` became `use lorica_*`.

## Removed Components

The following upstream crates and features were **deleted** during the fork:

| Removed | Reason |
|---------|--------|
| `pingora-openssl` | Lorica uses rustls exclusively |
| `pingora-boringssl` | Lorica uses rustls exclusively |
| `pingora-s2n` | Lorica uses rustls exclusively |
| Conditional TLS compilation (`#[cfg]` blocks) | Only rustls remains |
| Sentry integration | Cloudflare-specific observability |
| `cf-rustracing` | Cloudflare-specific tracing |
| Example binaries | Replaced by Lorica's own binary |
| Windows support (787 lines) | Linux-only project |

## Added Crates (Lorica-specific)

These crates do not exist in upstream Pingora:

| Crate | Purpose |
|-------|---------|
| `lorica` | CLI binary, supervisor, worker orchestration |
| `lorica-api` | axum REST API, auth, session management, RBAC |
| `lorica-config` | SQLite store, versioned migrations, TOML export/import |
| `lorica-dashboard` | Svelte 5 frontend embedded via rust-embed |
| `lorica-waf` | WAF engine, OWASP rules, IP blocklist |
| `lorica-notify` | Alert dispatch (stdout, SMTP, webhook, Slack) |
| `lorica-bench` | SLA monitoring, load testing engine |
| `lorica-worker` | fork+exec worker isolation, socket passing |
| `lorica-command` | Protobuf supervisor-worker command channel |
| `lorica-acme` | Pure ACME core: HTTP-01 / DNS-01 issuance driver, DNS challengers (Cloudflare / Route53 / OVH) |
| `lorica-metrics` | Shared Prometheus registry + cross-worker counter aggregation |
| `lorica-challenge` | Bot-protection challenge engine (PoW / captcha / cookie) |
| `lorica-geoip` | GeoIP / ASN country and network lookups |
| `lorica-shmem` | Anonymous `memfd` shared region for per-IP WAF flood / auto-ban counters |
| `lorica-tls` | SNI resolver, hot-swap, encrypted key storage (extends upstream TLS) |

## Comparing with Upstream

To compare Lorica's forked crates against upstream Pingora:

```bash
# Fetch upstream changes
git fetch upstream

# Compare a specific forked crate (account for renaming)
# Example: compare lorica-core against pingora-core
diff <(git show upstream/main:pingora-core/src/server.rs) lorica-core/src/server.rs

# List files changed in a forked crate
diff -rq <(git archive upstream/main pingora-proxy/src | tar -tf -) \
     <(ls lorica-proxy/src/)
```

### Name mapping for diffs

When comparing files across repositories, apply these substitutions:

- Directory: `pingora-{name}` - `lorica-{name}` (except `pingora-load-balancing` - `lorica-lb`)
- Cargo.toml package names: `pingora-{name}` - `lorica-{name}`
- Rust imports: `pingora_{name}` - `lorica_{name}`
- Feature flags: `pingora_` prefix - `lorica_` prefix (where applicable)

### What to check on upstream updates

1. **Security patches** in `pingora-core`, `pingora-proxy`, `pingora-http` - apply to corresponding `lorica-*` crates
2. **Performance improvements** in connection pool, load balancing, cache
3. **New TLS features** in `pingora-rustls` (Lorica's TLS is based on this)
4. **Breaking API changes** that affect `lorica-proxy` integration points

## Upstream sync record

Each release cycle that pulls upstream commits into the forked crates is
recorded here, most recent first. Commit ids are upstream `main` ids
(`git fetch upstream`). `docs/backlog.md` #81 carries the reasoning per
commit; the `[1.7.0]` CHANGELOG entries describe the user-visible effect.

| Cycle | Upstream range | Ported | Not ported (deliberate) |
|-------|----------------|--------|-------------------------|
| 1.7.0 (2026-09-09) | fork baseline to `09696b51` (2026-08-25) | `aece9932`, `6e2158d5` (re-implemented on the `RwLock` pool), `d5ade3a2`, `e21646be`, `f486cd84`, `b8aacad8`, `28c18e6b` + `ca23f166` (source, not the integration tests), `ff6693b7`, `d248583f` (source), `0c081493`, `7166d81e`, `6dcc236a`, `5bec4059`, `915590a9`, `3e657e2f` + `3dd51643` | proxy task API family `d7728cac`, `5a822047`, `8683056e`, `7142ad46`, `9c16af9c`, `17325ff4`, `b90d4203` and the six April feature commits it sits on (backlog #83); feature commits `21140569`, `4a9a34c5`, `600c5c0d`, `402acae5` |
| 1.5.8 (2026-06-05) | `0.8.1` | bounded HTTP/2 server limits (`default_h2_options`) | - |

How a commit is ported: `git format-patch -1 <sha>`, rename the paths and
identifiers per the mapping above, then `git -c rerere.enabled=false apply
--3way`. A hunk that does not apply is ported by hand; the fork's
`Box<HttpSession>` in `H2Accept::Session` and its `RwLock<HashMap>`
connection pool are the two places upstream has since diverged. Never
stage a file that still carries conflict markers: rerere would record the
broken state as a resolution.

## Attribution

See [NOTICE](NOTICE) for full attribution. Lorica is licensed under Apache-2.0, same as upstream Pingora.
