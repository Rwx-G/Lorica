# Story 4.4: Production Packaging

**Epic:** [Epic 4 - Production](../prd/epic-4-production.md)
**Status:** Draft
**Priority:** P2
**Depends on:** Epic 1 complete

---

As an infrastructure engineer,
I want to install Lorica via `apt install lorica`,
so that deployment is simple and follows standard Linux conventions.

## Acceptance Criteria

1. `.deb` package build pipeline (GitHub Actions or equivalent)
2. Package includes: binary, systemd unit file, default data directory (`/var/lib/lorica`)
3. Post-install script: create lorica system user, set directory permissions, enable service
4. Post-install output: display dashboard URL and temporary credentials
5. Upgrade-safe: database and data directory preserved on package upgrade
6. Static binary also available as GitHub release artifact
7. Package signing for apt repository trust

## Integration Verification

- IV1: `apt install lorica` on a clean Debian/Ubuntu system results in running service
- IV2: `apt upgrade lorica` preserves existing configuration and database
- IV3: `apt remove lorica` stops the service, `apt purge lorica` removes data directory

## Tasks

- [ ] Set up GitHub Actions CI (cargo test, clippy, fmt)
- [ ] Set up release build pipeline (cross-compilation: x86_64, aarch64)
- [ ] Create debian packaging files (control, postinst, prerm, postrm)
- [ ] Implement post-install script (create user, set permissions, enable service)
- [ ] Implement post-install credential display
- [ ] Implement upgrade-safe packaging (conffiles, data dir preservation)
- [ ] Set up apt repository with package signing
- [ ] Create GitHub release workflow (binary + .deb artifacts)
- [ ] Test fresh install on Debian/Ubuntu
- [ ] Test upgrade preserves data
- [ ] Test remove/purge behavior

## Dev Notes

- Use cargo-deb or nfpm for .deb packaging
- System user: `lorica` (no login shell)
- Data directory: `/var/lib/lorica/` (owned by lorica user)
- Binary location: `/usr/bin/lorica`
- Config/service: `/etc/systemd/system/lorica.service`
- Post-install displays: "Dashboard: https://localhost:9443 | Password: <random>"
