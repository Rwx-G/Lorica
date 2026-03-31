# Lorica Hardening Guide

**Author:** Romain G.
**Version:** 1.0
**Date:** 2026-03-31

## Overview

This guide covers security best practices for deploying Lorica in production. Lorica ships with secure defaults, but operators should review these settings for their specific environment.

## 1. Network Configuration

### Management API

The management API binds to **localhost only** (127.0.0.1:9443) by default. Never expose it to the network.

```bash
# CORRECT - default, localhost only
lorica --management-port 9443

# WRONG - do NOT put management behind a public reverse proxy
# The dashboard has no CSRF tokens for cross-origin requests
```

If remote access to the dashboard is needed, use an SSH tunnel:
```bash
ssh -L 9443:localhost:9443 user@lorica-host
```

### Proxy Ports

- **HTTP (8080)**: Use for redirect-to-HTTPS only, or for internal-only traffic
- **HTTPS (8443)**: Primary public-facing port with TLS termination

### Firewall Rules

```bash
# Allow proxy traffic
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 8443 -j ACCEPT

# Block management from network (redundant with localhost binding, defense-in-depth)
iptables -A INPUT -p tcp --dport 9443 -j DROP
```

## 2. TLS Configuration

### Certificate Management

- Use **ACME/Let's Encrypt** for automatic certificate provisioning when possible
- Use **DNS-01 challenge** if port 80 is not reachable from the Internet
- Set certificate **warning threshold** to 30 days and **critical threshold** to 7 days
- Enable **auto-renewal** for ACME certificates
- Self-signed certificates should only be used for testing

### TLS Backend

Lorica uses **rustls** exclusively (no OpenSSL). This provides:
- TLS 1.2 and 1.3 only (no SSLv3, TLS 1.0, 1.1)
- Strong cipher suites only (ring crypto provider)
- Certificate verification for upstream TLS backends

## 3. Authentication

### Admin Password

- Lorica generates a random password on first run - **change it immediately**
- Minimum password length: 12 characters
- The password is hashed with **Argon2** (memory-hard, resistant to GPU attacks)
- Failed login attempts are rate-limited (429 after threshold)

### Session Management

- Sessions use **HTTP-only** cookies (not accessible via JavaScript)
- Sessions are stored in-memory (cleared on restart)
- No session persistence across restarts by design (forces re-authentication)

## 4. WAF Configuration

### Recommended Setup

1. **Enable WAF in Detection mode** first to observe traffic patterns
2. Review WAF events in the dashboard for false positives
3. **Switch to Blocking mode** once confident
4. Add **custom rules** for application-specific threats

### IP Blocklist

- Enable the IPv4 blocklist (800k+ known malicious IPs from Data-Shield)
- The list auto-refreshes every 6 hours
- Manual reload available via dashboard or API

### Custom Rules

- Use the Security > Custom Rules tab to add application-specific patterns
- Severity 5 = critical, 4 = high, 3 = medium, 1-2 = low
- Test patterns in Detection mode before switching to Blocking

## 5. Process Isolation

### Worker Mode

For production deployments, use worker mode:
```bash
lorica --workers 4  # one per CPU core
```

This provides:
- Process-level isolation between workers
- Crash recovery with automatic restart and exponential backoff
- Independent memory spaces (one worker crash doesn't affect others)

### File Permissions

```bash
# Data directory: owned by lorica user
chown -R lorica:lorica /var/lib/lorica
chmod 700 /var/lib/lorica

# Database file: read-write for lorica only
chmod 600 /var/lib/lorica/lorica.db
```

### systemd Hardening

The packaged systemd unit (`lorica.service`) includes:
- `NoNewPrivileges=yes`
- `ProtectSystem=strict`
- `ProtectHome=yes`
- `ReadWritePaths=/var/lib/lorica`

## 6. Monitoring

### SLA Monitoring

- Configure **SLA targets** per route (default 99.9%)
- Enable **active probes** for critical routes to detect outages during low-traffic periods
- Set up **notification channels** (email/webhook) for SLA breach alerts

### Prometheus Metrics

- The `/metrics` endpoint is accessible without authentication
- If exposed, ensure network-level access control (firewall or Prometheus scrape config)
- Key metrics to alert on:
  - `lorica_http_requests_total` with high error rates
  - `lorica_backend_health` transitions to unhealthy
  - `lorica_cert_expiry_days` below threshold

### Load Testing

- Use built-in load testing with **safe limits** (configurable in settings)
- The **CPU circuit breaker** (90% threshold) automatically aborts tests that threaten proxy performance
- Always test in staging before production

## 7. Backup and Recovery

### Database Backup

```bash
# SQLite with WAL mode - safe to copy while running
cp /var/lib/lorica/lorica.db /backup/lorica-$(date +%Y%m%d).db
```

### Configuration Export

Use the dashboard Settings > Export to create a TOML backup of all configuration. This includes routes, backends, certificates, and settings but **excludes** private keys for security.

### Recovery

1. Install Lorica on new host
2. Copy database file to `/var/lib/lorica/lorica.db`
3. Or: use Settings > Import with the TOML backup

## 8. Audit Checklist

Run this checklist periodically:

- [ ] Admin password changed from default
- [ ] Management API not exposed to network
- [ ] TLS certificates not expired or expiring soon
- [ ] WAF enabled on all public-facing routes
- [ ] IP blocklist enabled and refreshing
- [ ] SLA monitoring active on critical routes
- [ ] Notification channels configured and tested
- [ ] Worker mode enabled for production
- [ ] File permissions correct on data directory
- [ ] Prometheus metrics collected by monitoring system
- [ ] Config backup taken within last 7 days
