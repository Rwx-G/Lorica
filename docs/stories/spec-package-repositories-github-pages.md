---
title: 'Signed apt and dnf repositories on GitHub Pages'
type: 'feature'
created: '2026-11-13'
status: 'done'
baseline_commit: '607a32c3fd741ee3c19c30d8ada62608b2b809c3'
route: 'dispatch'
review_loop_iteration: 0
context: []
---

<frozen-after-approval reason="human-owned intent - do not modify unless human renegotiates">

## Intent

**Problem:** Operators install Lorica by downloading a `.deb` or `.rpm` from the release page by hand, so `apt upgrade` and `dnf upgrade` never see a new version.

**Approach:** The CI release job, which already holds the signing key and the verified packages, builds a signed apt repository and a signed dnf repository holding only the release being published, and a following job deploys them to GitHub Pages. Each release replaces the whole site.

**Decisions (2026-11-13):**
- Hosted on this repository's own Pages, `https://rwx-g.github.io/Lorica/` (`apt/`, `rpm/`), deployed by `actions/deploy-pages` with the job's OIDC identity. No dedicated repository, no PAT.
- Both apt and dnf repositories ship in this change.

## Boundaries & Constraints

**Always:** The repository holds exactly one version: the latest release. Index metadata (`InRelease`, `Release.gpg`, `repomd.xml.asc`) is signed with the project key `B6E37EA916841674`, verified against `docs/lorica-signing-key.asc` before upload. Signing stays inside the `release` job. A tag lower than the highest published release never replaces the site. The client config files operators download (`lorica.sources`, `lorica.repo`) are the ones the PR-time test exercises.

**Never:** No `.deb`/`.rpm` committed to git. No new long-lived token or secret. No second job holding the private key. No new Rust or npm dependency. No Pages build from a branch (`gh-pages`).

## I/O & Edge-Case Matrix

| Scenario | Input / State | Expected Output / Behavior | Error Handling |
|----------|--------------|---------------------------|----------------|
| Release | tag `vX.Y.Z`, highest version | site replaced with X.Y.Z only; `apt install lorica` / `dnf install lorica` get it | repo build or verification fails -> release not published, job re-runnable |
| Older-line tag | tag lower than an already published release | release published, site left untouched | step logs why it skipped |
| Deploy failure | Pages deploy job fails | release already published | re-run the deploy job alone; the artifact is still there |
| Wrong key | client keyring holds another key | `apt-get update` refuses the repository | PR test asserts the refusal |

</frozen-after-approval>

## Code Map

- `.github/workflows/ci.yml:853-946` -- `release` job: downloads `lorica-deb`/`lorica-rpm`, imports the key (`$RUNNER_TEMP/gpg-pass`), signs, verifies against the published key, publishes the release (draft-resume logic). Insert site build + verification + `upload-pages-artifact` before "Publish the release"; add `createrepo-c` to the existing rpm-tools install.
- `.github/workflows/ci.yml:542-615` -- `test-deb-install`, shape to copy for the PR-time job (needs `package`, downloads `lorica-deb`).
- `.github/workflows/ci.yml:10-12` -- top-level `permissions: contents: read`; the deploy job adds `pages: write`, `id-token: write` for itself only.
- `.github/workflows/ci.yml:819-822` -- `verify-tag.needs`: the new PR-time test joins this list so a release cannot ship a repo layout that failed.
- `dist/build-deb.sh`, `dist/build-rpm.sh` -- package names `lorica_<v>_amd64.deb`, `lorica-<v>-1.x86_64.rpm`. Do not change them.
- `docs/lorica-signing-key.asc` -- published key, copied to the site root.
- `README.md:160-171` (Quick Start install) and `README.md:898-924` (Package Verification) -- add repository install, keep manual download as alternative.
- `docs/installation.md:12-25` -- same install block.
- `CHANGELOG.md` `[Unreleased] / Added`.

## Tasks & Acceptance

**Execution:**
- [x] `dist/build-package-repo.sh` -- new script: args `<out-dir> <base-url> <key-id> <deb> <rpm>`, optional `GPG_PASSPHRASE_FILE`; builds `apt/` (pool, `dists/stable/main/binary-amd64/Packages{,.gz}`, `Release`, `InRelease`, `Release.gpg`, `lorica.sources`), `rpm/` (package, `repodata/` via `createrepo_c`, `repomd.xml.asc`, `lorica.repo`), and `lorica-signing-key.asc` at the root -- one script used by both the release job and the PR test, so what is tested is what ships.
- [x] `.github/workflows/ci.yml` -- new `test-package-repo` job (PR + main + tag): throwaway key, signs the rpm with it, builds the site with base URL `http://127.0.0.1:8000`, serves it, then `ubuntu:22.04` (oldest apt supported) `apt-get update && apt-get install --download-only lorica` and `fedora:latest` `dnf install lorica` using the generated client files; asserts `apt-get update` fails when the keyring holds `docs/lorica-signing-key.asc` instead. Add it to `verify-tag.needs`.
- [x] `.github/workflows/ci.yml` -- `release` job: highest-version guard, build site with base URL `https://rwx-g.github.io/Lorica`, verify signatures against the published key, `actions/upload-pages-artifact@v5`; new `deploy-pages` job (`needs: release`, `environment: github-pages`, `actions/deploy-pages@v5`) gated on the guard output.
- [x] `README.md`, `docs/installation.md` -- repository install as the primary path, manual download kept.
- [x] `CHANGELOG.md` -- `[Unreleased] / Added` entry.

**Acceptance Criteria:**
- Given a PR, when CI runs, then `test-package-repo` passes on the packages that PR built.
- Given the site built for a release, when the published key verifies `InRelease`, `Release.gpg` and `repomd.xml.asc`, then the release proceeds; any mismatch fails the job before the release is published.
- Given Pages enabled with source "GitHub Actions" and the `github-pages` environment allowing `v*` tags, when a tag release finishes, then `https://rwx-g.github.io/Lorica/apt/dists/stable/InRelease` lists exactly that version.

## Implementation Notes

- Review pass 1 patches (triage rows 1-11): the script takes a `<public-key>` file copied verbatim to the site root (release passes `docs/lorica-signing-key.asc`); `lorica.repo` trusts `file:///etc/pki/rpm-gpg/RPM-GPG-KEY-lorica`, never a key URL on the site; the guard lives in `dist/is-highest-release.sh` (pre-releases never publish), asserted on fixed inputs in `test-package-repo` and asked again inside `deploy-pages` under the `pages` group; the PR job signs with a passphrase-protected throwaway key through `GPG_PASSPHRASE_FILE`, installs with dnf on Fedora and Rocky Linux 9, and checks dnf refuses another key; the release checks the rpm version and the production URLs in both client files; Pages artifact kept 30 days.
- Re-verified after the patches: local Docker mirror passes (apt fetch + `NO_PUBKEY` refusal on 22.04; dnf install on Fedora 44 and Rocky 9; dnf refusal on both; build without the passphrase file fails), the 7 guard assertions pass, `actionlint` and `shellcheck` clean, scripts LF.
- The Pages artifact is named `package-repositories-<run_attempt>` and handed to `deploy-pages` through a job output: artifact names are unique within a run, so a re-run `release` job would otherwise collide with the artifact its failed attempt uploaded, and a re-run deploy job still finds the release attempt's artifact.
- Matrix coverage: happy path and wrong-key rows run in `test-package-repo` (replayed locally in Docker: apt on ubuntu:22.04 fetched the built `.deb` byte for byte, refused under the project key with `NO_PUBKEY`, dnf on Fedora installed). The older-line guard was exercised locally on sample release lists (higher, lower, equal, none); it only runs for real on a tag. The deploy re-run row needs a real tag run and is not testable before.
- `actionlint` clean on `ci.yml`, `shellcheck` clean on the script.

## Spec Change Log

## Review Triage Log

Pass 1 (2026-11-13), layers: blind-hunter, edge-case-hunter, verification-gap.

| # | Finding | Verdict | Evidence | Route |
|---|---------|---------|----------|-------|
| 1 | dnf refusal under another key never tested (VG, BH) | medium | Only apt has a negative step; dropping `repo_gpgcheck`/`gpgcheck` from `lorica.repo` keeps CI green while README claims refusal | patch |
| 2 | `GPG_PASSPHRASE_FILE` branch never runs before a tag (VG) | medium | Throwaway key has no passphrase and the PR job never sets the variable; release is the first run | patch |
| 3 | Highest-release guard untested (VG) | medium | Inline in `release`, reachable on tags only; an inverted test rolls the site back silently | patch |
| 4 | Pre-release tags mis-ordered by `sort -V` (BH, ECH) | low | `sort -V` ranks `1.11.0-rc.1` above `1.11.0`; no such tag exists yet, fix is a filter in the guard | patch |
| 5 | Two tags released close together can deploy out of order (BH, ECH) | medium | Guard runs before either release is published; `pages` concurrency queues, does not order; violates the "never rolls back" constraint | patch |
| 6 | rpm index version and client-file base URLs unchecked at release (VG, BH, ECH) | medium | Only apt `Packages` is checked; CI builds client files with 127.0.0.1, so a wrong production URL ships unseen | patch |
| 7 | RHEL 9 (dnf4) documented but untested (BH) | medium | Test runs `fedora:latest` (dnf5) only; glibc floor makes EL9 a supported target | patch |
| 8 | Site key exported from the CI keyring, not the published file (BH) | low | Fingerprint-only check would miss UID/self-sig/expiry drift; fix is passing the public key file | patch |
| 9 | Pages artifact retention defaults to 1 day (ECH) | medium | `upload-pages-artifact` default `retention-days: 1`; a deploy re-run after a day fails and the release cannot be re-run | patch |
| 10 | `gpgkey=` on the same site as the packages (ECH) | high | A compromised site serves a new key; `dnf -y` imports it from `gpgkey` and accepts attacker-signed packages. Key must be a local file the operator fetched and checked once | patch |
| 11 | CHANGELOG says CI installs on Ubuntu 22.04 (ECH) | low | The apt step is `--download-only` + `cmp` | patch |
| 12 | CDN cache window after a release can mix old and new index files (BH) | low | Transient (~10 min Pages cache), a retry clears it; the fix keeps the previous release, against the "latest only" intent | reject |
| 13 | Fingerprint check not a command; curl/gpg prerequisites (BH) | low | Docs already name `gpg --show-keys`; cosmetic | reject |
| 14 | One-time Pages settings only in a YAML comment (BH) | low | Settings are applied once before merge and persist; a release-time probe needs `pages: read` in the key-holding job | reject |
| 15 | Removal / switch-over / amd64-only docs (BH) | low | Switching needs no step (the repo upgrades an installed package); removal is the two files the snippet wrote | reject |
| 16 | Spec missing from the reviewed diff (BH) | false | Excluded on purpose: the claims file goes to the edge-case layer only | reject |

## Design Notes

Repository settings, done once outside the code: Pages source = GitHub Actions; the `github-pages` environment created by that switch only allows the default branch, and the release runs on a tag ref, so a `v*` tag rule must be added or the deploy is refused.

apt layout uses suite `stable`, component `main`, arch `amd64`, deb822 client file with `Signed-By: /etc/apt/keyrings/lorica.asc` (armored keyrings accepted from apt 2.4, the Ubuntu 22.04 floor that glibc 2.34 already sets).

## Verification

**Commands:**
- Local Docker run of `dist/build-package-repo.sh` with a throwaway key, then the same `ubuntu:22.04` and `fedora:latest` client steps as the CI job -- expected: both resolve and fetch `lorica` from the served tree.
- `docker run --rm -v "$PWD:/repo" -w /repo rhysd/actionlint:latest` -- expected: no finding on `ci.yml`.
