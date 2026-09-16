# Version Bump Checklist

When bumping the version, update ALL of these files:

## Product crate versions (package version)
- [ ] `lorica/Cargo.toml` - `version`
- [ ] `lorica-api/Cargo.toml` - `version`
- [ ] `lorica-metrics/Cargo.toml` - `version` (follows product since v1.6.0)
- [ ] `lorica-config/Cargo.toml` - `version`
- [ ] `lorica-dashboard/Cargo.toml` - `version`
- [ ] `lorica-bench/Cargo.toml` - `version`
- [ ] `lorica-worker/Cargo.toml` - `version`
- [ ] `lorica-command/Cargo.toml` - `version`
- [ ] `lorica-shmem/Cargo.toml` - `version`
- [ ] `lorica-geoip/Cargo.toml` - `version` (follows product since v1.4.0)
- [ ] `lorica-challenge/Cargo.toml` - `version` (follows product since v1.4.0)
- [ ] `lorica-waf/Cargo.toml` - `version` (first-party; follows product since v1.6.0)
- [ ] `lorica-notify/Cargo.toml` - `version` (first-party; follows product since v1.6.0)
- [ ] `lorica-acme/Cargo.toml` - `version` (first-party; follows product since v1.6.0)
- [ ] `lorica-cluster/Cargo.toml` - `version` (first-party; follows product since v1.7.0)

## Internal dependency references (cross-crate deps)
- [ ] `lorica/Cargo.toml` - lorica-config, lorica-api, lorica-bench, lorica-worker, lorica-command, lorica-shmem, lorica-geoip, lorica-challenge, lorica-waf, lorica-notify versions
- [ ] `lorica-api/Cargo.toml` - lorica-acme, lorica-config, lorica-dashboard, lorica-bench, lorica-metrics, lorica-waf, lorica-notify versions
- [ ] `lorica-bench/Cargo.toml` - lorica-config, lorica-metrics, lorica-notify versions
- [ ] `lorica-notify/Cargo.toml` - lorica-metrics version

## Frontend and API spec
- [ ] `lorica-dashboard/frontend/package.json` - `version`
- [ ] `lorica-dashboard/frontend/package-lock.json` - the root `version`, twice: once at the top of the file and once in the `packages.""` entry (`pnpm-lock.yaml` does not record it). **Do not blind-replace**: a dependency can carry the same version string (at 1.7.0 it was `node_modules/esquery`), so replace the two root entries and leave the rest.
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
  lorica-tls, tinyufo

## Release tag (signed)

Once the release commit is on `main`, the tag is **annotated and GPG-signed**.
Never lightweight, never unsigned:

```bash
git tag -s -a vX.Y.Z -m "vX.Y.Z: <merge commit subject, without the PR number>"
git push origin vX.Y.Z
```

The key is `B6E37EA916841674` (`Rwx-G (Lorica Project on Github)`): the same
key CI uses to sign the `.deb` and `.rpm`, and the same one published at
`docs/lorica-signing-key.asc` so operators can verify those packages. Signing
the tag extends that chain back from the artifact to the commit it was built
from.

Set once per clone, so the flag is not something to remember:

```bash
git config user.signingkey B6E37EA916841674
git config tag.gpgsign true
```

Enforcement lives in the `verify-tag` job of `.github/workflows/ci.yml`: on a
`v*` tag push it imports the published key and the Release job does not run
unless the tag is an annotated object carrying a good signature from that key.

Tags up to and including `v1.7.2` predate this and are unsigned; `v1.6.0` is
lightweight, and the signature visible on it belongs to GitHub's web-flow key
on the squash-merge commit it points at, not to the project key. v1.7.3 was
never tagged (its content ships in v1.7.4), so signed tags start at `v1.7.4`.

## Drift checks (v1.5.2 audit M-15)

A handful of user-visible numbers live in code AND in marketing-style docs, and the docs have drifted twice in the past. Re-run these greps when editing `lorica-waf/` or bumping the version, and update the docs if the numbers moved :

```bash
# Test counts quoted in README.md ("Product crates only (N tests)",
# "Pingora-forked crates (N tests)", the Vitest figure) and in
# CONTRIBUTING.md. They drift every cycle that adds a test and nothing
# recomputes them. Sum the per-binary results rather than trusting the
# last edit:
cargo test <the README product-crate list> 2>&1 \
  | grep -oE 'test result: ok\. [0-9]+ passed' | grep -oE '[0-9]+' \
  | python3 -c 'import sys; print(sum(int(x) for x in sys.stdin))'
# Same for the forked list, and `ls lorica/tests/*.rs | wc -l` for the
# count of end-to-end binaries. Note the forked list needs `-p TinyUFO`,
# not `-p tinyufo`: the package name is case-sensitive and the lowercase
# form fails resolution.

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
