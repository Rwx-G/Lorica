# Fork Information

Lorica is a fork of [Cloudflare Pingora](https://github.com/cloudflare/pingora), modified to serve as a dashboard-first reverse proxy product.

## Origin

| Field | Value |
|-------|-------|
| Upstream repository | <https://github.com/cloudflare/pingora> |
| Upstream license | Apache-2.0 |
| Fork date | 2026-03-29 |
| Upstream version at fork | 0.4.x (commit range up to `0.4.0` release) |
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
| `lorica-api` | axum REST API, auth, session management |
| `lorica-config` | SQLite store, migrations, TOML export/import |
| `lorica-dashboard` | Svelte 5 frontend embedded via rust-embed |
| `lorica-waf` | WAF engine, OWASP rules, IP blocklist |
| `lorica-notify` | Alert dispatch (stdout, SMTP, webhook) |
| `lorica-bench` | SLA monitoring, load testing engine |
| `lorica-worker` | fork+exec worker isolation, socket passing |
| `lorica-command` | Protobuf supervisor-worker command channel |
| `lorica-tls` | SNI resolver, hot-swap, ACME (extends upstream TLS) |

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

## Attribution

See [NOTICE](NOTICE) for full attribution. Lorica is licensed under Apache-2.0, same as upstream Pingora.
