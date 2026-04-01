# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x   | Yes       |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Instead, please report vulnerabilities by emailing: **romain@rwx-g.fr**

Include:

- Description of the vulnerability
- Steps to reproduce
- Potential impact assessment
- Suggested fix (if any)

## Response Timeline

- **Acknowledgement:** within 48 hours
- **Initial assessment:** within 7 days
- **Fix or mitigation:** within 30 days for critical issues

## Security Measures

Lorica includes several built-in security layers:

- WAF engine with OWASP CRS-inspired rules
- Rate limiting and auto-ban protection
- AES-256-GCM encryption for certificate private keys at rest
- Session-based authentication with secure cookies
- systemd hardening (PrivateTmp, NoNewPrivileges, ProtectSystem)
- Management port bound to localhost only

See [docs/security/hardening-guide.md](docs/security/hardening-guide.md) for the full hardening guide.

## Dependency Auditing

`cargo audit` runs in CI on every push. We monitor advisories and update dependencies promptly.
