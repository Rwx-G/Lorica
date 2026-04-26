# Version Bump Checklist

When bumping the version, update ALL of these files:

## Product crate versions (package version)
- [ ] `lorica/Cargo.toml` - `version`
- [ ] `lorica-api/Cargo.toml` - `version`
- [ ] `lorica-config/Cargo.toml` - `version`
- [ ] `lorica-dashboard/Cargo.toml` - `version`
- [ ] `lorica-bench/Cargo.toml` - `version`
- [ ] `lorica-worker/Cargo.toml` - `version`
- [ ] `lorica-command/Cargo.toml` - `version`
- [ ] `lorica-shmem/Cargo.toml` - `version`
- [ ] `lorica-geoip/Cargo.toml` - `version` (follows product since v1.4.0)
- [ ] `lorica-challenge/Cargo.toml` - `version` (follows product since v1.4.0)

## Internal dependency references (cross-crate deps)
- [ ] `lorica/Cargo.toml` - lorica-config, lorica-api, lorica-bench, lorica-worker, lorica-command, lorica-shmem, lorica-geoip, lorica-challenge versions
- [ ] `lorica-api/Cargo.toml` - lorica-config, lorica-dashboard, lorica-bench versions
- [ ] `lorica-bench/Cargo.toml` - lorica-config version

## Frontend and API spec
- [ ] `lorica-dashboard/frontend/package.json` - `version`
- [ ] `lorica-api/openapi.yaml` - `version`

## Documentation
- [ ] `README.md` - version badge
- [ ] `CHANGELOG.md` - move `[Unreleased]` to `[x.y.z] - YYYY-MM-DD`

## Packaging
- [ ] `dist/rpm/lorica.spec` - `Version` field

## NOT bumped (forked crates stay at their own version)
- lorica-core, lorica-proxy, lorica-http, lorica-error, lorica-pool,
  lorica-timeout, lorica-header-serde, lorica-runtime, lorica-ketama,
  lorica-lb, lorica-cache, lorica-memory-cache, lorica-lru, lorica-limits,
  lorica-waf, lorica-notify, lorica-tls, tinyufo

## Drift checks (v1.5.2 audit M-15)

A handful of user-visible numbers live in code AND in marketing-style docs, and the docs have drifted twice in the past. Re-run these greps when editing `lorica-waf/` or bumping the version, and update the docs if the numbers moved :

```bash
# WAF rule count (code = 49 today : 46 general in `RuleSet::rules` +
# 3 header-scoped in `RuleSet::header_scoped` since v1.5.2 H-3).
# Authoritative source is `lorica-waf/src/rules.rs` ; one
# `description: "..."` per rule struct (both vecs).
grep -c 'description: "' lorica-waf/src/rules.rs
grep -rn 'OWASP-inspired\|OWASP CRS' README.md COMPARISON.md docs/

# IP blocklist size (~80k today, sourced from Data-Shield IPv4
# Blocklist). The ~80k figure tracks the upstream feed ; if a
# major refresh moves the count by an order of magnitude, the
# docs follow.
grep -rn '80k\|800k\|known malicious IPs' README.md docs/ CHANGELOG.md
```

Past drifts caught by this audit :
- threat-model.md said `18 rules` and `800k+ IPs` for ~6 months while code was `49` and `~80k`.
- source-tree.md said `18 OWASP-inspired regex rules` and `800k+ IPs` (same shape).
- hardening-guide.md said `800k+`.

CHANGELOG entries are immutable history (a v1.0.0 entry that says `39 rules` is correct - that was the count then) and stay as written.
