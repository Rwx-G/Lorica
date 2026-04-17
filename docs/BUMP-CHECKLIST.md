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
