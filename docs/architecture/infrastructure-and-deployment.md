# Infrastructure and Deployment

## Existing Infrastructure

**Current Deployment:** N/A - new product. Target: Linux servers managed by the author.
**Infrastructure Tools:** systemd for service management, apt for package management.
**Environments:** Production only (single-purpose tool, no staging needed for the proxy itself).

## Enhancement Deployment Strategy

**Deployment Approach:**
1. Primary: `.deb` package via apt repository
2. Secondary: Static binary download from GitHub releases
3. Future: Docker image, RPM package

**Infrastructure Changes:**
- systemd service file (`lorica.service`) with security hardening directives
- Data directory: `/var/lib/lorica/` (SQLite database, runtime state)
- Log output: stdout captured by systemd journal

**Pipeline Integration:**
- GitHub Actions for CI (cargo test, cargo clippy, cargo fmt --check)
- GitHub Actions for release builds (x86_64 only)
- GitHub Actions for .deb package building and apt repository publishing

## Rollback Strategy

**Rollback Method:** `apt install lorica=<previous-version>`. Database migrations are forward-only but designed to be non-destructive (additive columns, new tables). In worst case, restore database from TOML export backup.

**Risk Mitigation:**
- Auto-backup of database before migration on upgrade
- TOML export triggered automatically before package upgrade (post-install script)
- Binary is statically linked - no shared library version conflicts

**Monitoring:** Structured JSON logs to stdout -> journald -> SIEM/XDR. Prometheus endpoint for metrics scraping. Dashboard for visual monitoring.
