# Certificate Filesystem Export - Threat Model

**Feature:** v1.4.1 `cert_export_*` + `cert_export_acls` + `GET /api/v1/certificates/:id/download`
**Author:** Romain G.
**Status:** Shipped. Disabled by default. Operator opt-in.

## 1. Purpose

The certificate filesystem export zone mirrors issued certificates
(ACME or self-signed) as plain PEM files under a configurable
directory so external tooling (Ansible, HAProxy sidecar, backup
jobs, `monit`, anything that watches a filesystem path) can pick up
the live bundle without talking to the management API.

This document enumerates the trust boundaries, the threat actors,
and the mitigations the v1.4.1 implementation takes. It is scoped to
the export feature - the wider Lorica threat model lives in
`docs/security/threat-model.md`.

## 2. Assets at risk

| Asset                                  | Sensitivity      | Where it lives                                          |
|----------------------------------------|------------------|---------------------------------------------------------|
| Private-key material (`privkey.pem`)   | CRITICAL         | On disk once the feature is enabled                     |
| Full certificate chain (`fullchain.pem`) | Moderate       | On disk once the feature is enabled                     |
| Operator session cookie                | HIGH             | Only on the dashboard / management API path             |
| Cert-export ACL rows                   | Low (metadata)   | `cert_export_acls` SQLite table                         |

The private key is the highest-value secret in any TLS deployment.
Every mitigation below is geared at making sure the key never leaves
the disk footprint the operator explicitly configured.

## 3. Trust boundaries

```
+---------------------+    over HTTPS + session cookie    +------------------+
|  Operator browser   |  <---------------------------->   | Management API   |
+---------------------+                                   +--------+---------+
                                                                   |
                                                                   | in-process
                                                                   v
                                                          +--------+---------+
                                                          | Lorica process   |
                                                          |  (lorica user)   |
                                                          +--------+---------+
                                                                   |
                                                                   | write() + chown()
                                                                   v
                                                          +--------+---------+
                                                          | /var/lib/lorica/ |
                                                          |  exported-certs/ |
                                                          +--------+---------+
                                                                   |
                                                                   | read (unprivileged user)
                                                                   v
                                                          +--------+---------+
                                                          | External tools   |
                                                          |  (Ansible, ...)  |
                                                          +------------------+
```

Trust boundary 1 (browser ↔ API) is the same as every other
dashboard action and reuses the existing session / CSRF /
rate-limit plumbing.

Trust boundary 2 (Lorica ↔ disk) is the new boundary v1.4.1
introduces. Everything below documents how that boundary is kept
narrow.

Trust boundary 3 (disk ↔ external consumer) is where the operator
takes ownership of securing the bundle. The systemd unit already
ships with `ReadWritePaths=/var/lib/lorica`, so only the lorica
service user (and root) can write into the export dir.

## 4. Adversaries

- **A1 - Malicious local user.** A regular Unix user on the host
  who did not get read access to the export directory but can still
  access the filesystem. Goal: exfiltrate a private key.
- **A2 - Authenticated operator with limited intent.** A legitimate
  dashboard user who types a bogus export directory or a
  path-traversal pattern into the ACL editor.
- **A3 - Unauthenticated network attacker.** Can reach the
  management port. Goal: read a cert bundle over HTTP.
- **A4 - Compromised Lorica process.** RCE in Lorica itself. Goal:
  pivot by writing keys to arbitrary paths outside the export dir.

## 5. Threats + mitigations

### T1 - Unintended world-readable key material (A1)

| | |
|-|-|
| **Scenario** | Operator enables the export but leaves the default file mode `0o644` or weaker. A colocated unprivileged user reads `privkey.pem`. |
| **Mitigation** | Default `cert_export_file_mode = 0o640` and `cert_export_dir_mode = 0o750`. Per-pattern ACL rows override the `chown` target so Ansible / HAProxy sidecars land in a dedicated Unix group without opening the dir. The dashboard surfaces a red warning banner at the top of the settings tab before the operator flips the enable toggle. |
| **Residual risk** | Operator deliberately weakens the modes (e.g. `0o666`). This is out of scope - the feature documents the safe default and the banner warns. |

### T2 - Path traversal via ACL pattern or export dir (A2, A4)

| | |
|-|-|
| **Scenario** | Operator or attacker submits `cert_export_dir = /etc/../tmp/..` or an ACL pattern of `../etc/passwd` hoping the exporter writes outside the configured zone. |
| **Mitigation** | Backend `validate_pattern` + `validate_absolute_path` reject any `/..`, trailing `/..`, leading dot, `*`-in-the-middle wildcard, or non-DNS character BEFORE the value is stored. The hostname sanitiser in `lorica-api::cert_export::sanitize_hostname` falls back to the opaque cert id when the domain contains unsafe bytes, so even a malformed row in the `certificates` table (e.g. a bad manual import) cannot produce a disk path containing `..`. Matching front-end validators mirror both checks at blur time. |
| **Residual risk** | None identified for the write path. Read-side traversal on `GET /api/v1/certificates/:id/download` is prevented by `sanitize_filename` which rejects any filename starting with `.` or containing `..`. |

### T3 - Race between concurrent renewals + external readers (A2, A4)

| | |
|-|-|
| **Scenario** | An external tool reads `privkey.pem` while the ACME renewal path is mid-way through writing the new key. Half-written content leaks or the tool consumes a zero-byte file. |
| **Mitigation** | Atomic write via stage-to-`.tmp` → `fsync` → `rename`. POSIX `rename(2)` is atomic within a filesystem, so an external reader always sees either the old full file or the new full file. A cross-mount `EXDEV` fallback copies the staged file onto the destination filesystem before renaming, preserving the same atomicity guarantee. |
| **Residual risk** | Readers that do not tolerate mid-cycle `ENOENT` (the `.tmp` briefly exists). Typical tools retry on ENOENT; this is a documented caveat. |

### T4 - Feature leak when disabled (A2, A4)

| | |
|-|-|
| **Scenario** | Operator toggles `cert_export_enabled=false` but the exporter keeps writing because the code path forgot to re-read the setting. |
| **Mitigation** | `export_certificate` short-circuits as the first statement when `settings.cert_export_enabled == false` OR `cert_export_dir.is_none()`. Unit test `export_is_noop_when_disabled` pins both branches. E2E smoke `run-cert-export-smoke.sh` re-verifies after the settings flip: `POST /cert-export/reapply` returns `enabled=false` and `exported=0`. |
| **Residual risk** | None identified. |

### T5 - Unauthorised download (A3)

| | |
|-|-|
| **Scenario** | Network attacker reaches the management port and issues `GET /api/v1/certificates/:id/download?part=key` to exfiltrate every key. |
| **Mitigation** | The download route is gated by the same `protected_routes` session layer as every other `/api/v1/*` endpoint. A second layer of defense in depth: `RateLimiter` caps the endpoint at 5 downloads / 60s per client IP (bucket shape reused from the login flow). Every call writes a `tracing::warn!` audit line with the client IP, cert id, domain, and selected part. An operator can grep the journal for the audit line after-the-fact. |
| **Residual risk** | An attacker who already has a valid session cookie can exfiltrate keys. This is the same risk as every other state-mutating endpoint; it is covered by the wider hardening guide (rotate the admin password, restrict management port to localhost + proxy, etc.). |

### T6 - ACL rule bypass via wildcard collision (A2)

| | |
|-|-|
| **Scenario** | Two ACL rows match the same hostname (e.g. `*.mibu.fr` and `*.prod.mibu.fr`). The operator expected the more specific one to win but a naive implementation might apply the first-inserted rule. |
| **Mitigation** | `resolve_cert_export_acl` ranks matches by specificity: exact hostname > wildcard suffix length > catch-all. The logic lives in `lorica-config::models::cert_export_acl` and is covered by unit tests that explicitly assert the ordering with the two-pattern-one-host scenario. |
| **Residual risk** | None - the ordering is deterministic and tested. |

### T7 - Missing CAP_CHOWN silently downgrades permissions (A2)

| | |
|-|-|
| **Scenario** | Operator configures `cert_export_owner_uid = 1001` (Ansible user). Lorica runs without `CAP_CHOWN`, so `nix::unistd::chown` returns `EPERM` and the file silently stays owned by the lorica process user. Ansible cannot read the bundle. |
| **Mitigation** | `apply_permissions` detects `EPERM` and returns `ExportOutcome::PermissionsSkipped` which is logged at `warn!`. The dashboard surfaces the outcome via the `/reapply` endpoint's `failed` count. The systemd unit documents the opt-in `CAP_CHOWN` in a comment block. |
| **Residual risk** | Operator ignores the warn line. This is documented in the settings tab hint text. |

### T8 - ENOSPC turns into a cascading renewal failure (A2)

| | |
|-|-|
| **Scenario** | The export filesystem fills up mid-renewal. An upstream ACME flow that depends on `export_certificate` returning `Ok` would otherwise fail and the operator loses the cert. |
| **Mitigation** | `export_certificate` is call-at-the-end-of-issuance and its failure is never propagated to the ACME caller. Every call path (`certificates::create_certificate`, `certificates::generate_self_signed`, `acme::http01`, `acme::dns01`, `acme::dns01_manual`) swallows the error into a `tracing::warn!` line. ENOSPC is surfaced as a dedicated `ExportError::DiskFull` variant so an operator grepping the journal can distinguish "quota ran out" from "unknown I/O error". |
| **Residual risk** | The in-DB certificate is still the source of truth; the disk copy can always be regenerated via `POST /cert-export/reapply` after clearing space. |

## 6. Explicit non-goals

- **No PKCS#12 output.** v1.4.1 ships PEM only. Operators who need
  a `.p12` bundle for a Java keystore can generate one from the PEM
  files with `openssl pkcs12 -export`.
- **No key encryption on disk.** The whole point of this feature is
  that the key lands in a form external tools can consume without
  first decrypting. If your threat model requires at-rest
  encryption, mount the export directory on an encrypted volume
  (LUKS, EBS-KMS) instead of adding application-level encryption
  that defeats the consumer-visibility goal.
- **No automated cleanup of orphaned hostnames.** If the operator
  deletes a cert in the dashboard, the on-disk directory is NOT
  removed. This is deliberate: a consumer that cached the path
  must see a stable filesystem layout. Removal is an explicit
  operator action (`rm -rf /var/lib/lorica/exported-certs/<host>`).
- **No mirror to remote storage.** v1.4.1 writes locally. S3 /
  remote-sync flavours are out of scope.

## 7. Deployment checklist

Operators enabling this feature should, in order:

1. Decide whether the bundle will be consumed by a specific Unix
   user. If yes, create the target group (`lorica-certs`), add the
   consumer's user to it, and plan to set `cert_export_group_gid`
   to its GID in the dashboard.
2. (If chown is required) Grant `CAP_CHOWN` to the systemd unit by
   editing `dist/lorica.service` (uncomment the `CAP_CHOWN` line on
   both `CapabilityBoundingSet` and `AmbientCapabilities`), or
   override via `systemctl edit lorica`.
3. If pointing `cert_export_dir` at a path OTHER than
   `/var/lib/lorica/exported-certs`, add the new path to
   `ReadWritePaths=` in the systemd unit (`ProtectSystem=strict`
   blocks writes everywhere else).
4. Keep `cert_export_file_mode` at `0o640` or stricter and
   `cert_export_dir_mode` at `0o750` or stricter.
5. Add an ACL row per pattern you intend to export. The catch-all
   `*` is intentionally not a default - an empty ACL table means
   no cert is exported even when the feature is on. Start with
   narrow patterns and widen only if necessary.
6. After the first export, `ls -l /var/lib/lorica/exported-certs/`
   and confirm the modes + ownership match expectations.

## 8. Related docs

- `docs/security/hardening-guide.md` - baseline systemd + TLS hygiene.
- `docs/security/threat-model.md` - wider Lorica threat model.
- `tests-e2e-docker/test-runner/run-cert-export-smoke.sh` -
  end-to-end coverage on every `run.sh` invocation.
