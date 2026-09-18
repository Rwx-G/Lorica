# API Design and Integration

> **Baseline note.** The endpoint list below is the v1.0 planning subset
> and predates the RBAC, ACME, AI-crawler, audit-log, hot-upgrade,
> cluster, and automation routes. There are now **two** authoritative,
> always-current contracts, and both are enforced against the live axum
> route tables by `lorica-api/tests/openapi_contract.rs`:
>
> - `lorica-api/openapi.yaml` - the management plane, scanned against
>   `src/server.rs`.
> - `lorica-api/openapi-automation.yaml` - the automation plane, scanned
>   against `src/automation/router.rs`. The test additionally checks that
>   the scope each operation documents is the scope the gate applies.
>
> Automation paths never appear in `openapi.yaml`: that document declares
> one server and one security scheme (the session cookie), which is false
> of the automation plane. A reader who checks only the first misses the
> entire automation surface. The README "REST API Reference" is the
> human-readable summary of the management plane.

## API Integration Strategy

**API Integration Strategy:** Two independent REST surfaces over HTTPS, on two separate listeners.

- **Management plane** (`--management-port`, loopback, always on). JSON request/response bodies, path prefix `/api/v1/`. All state mutations for a human operator go through it; the embedded dashboard and the `lorica` CLI subcommands are pure consumers.
- **Automation plane** (`--automation-listen`, opt-in, off when the flag is absent). Its own socket, its own accept loop, its own contract. Unlike the management listener it is not loopback by construction, because an automation usually runs on another host.

The two planes deliberately share no credential and no socket. A request arriving on the automation listener with a valid `lorica_session` cookie and no `Authorization` header is a 401, and the cookie is never read: there is no cookie layer, no CSRF layer and no session store in the automation router.

**Authentication (management plane):** Session-based. Login returns an HTTP-only secure cookie (`lorica_session`, `Secure`, `SameSite=Strict`, `Path=/api`). Sessions are **persisted**: the `sessions` table in SQLite is the source of truth, and the in-memory `HashMap` in front of it is a cache rebuilt from the table at startup, so sessions survive a restart rather than being dropped with the process. A lookup that misses the cache falls back to the table. Expiry is a 30-minute sliding window refreshed on use, and a GC tick purges both the cache and the rows past `expires_at`. In worker mode the supervisor owns the only session store; workers never read or write sessions. Rate limiting on the login endpoint (5 attempts per minute, keyed by client IP).

**Authentication (automation plane):** Never a session. The bearer value is either a static scoped token (`<public_id>.<secret>`, minted by `lorica automation token create`) or a GitLab OIDC ID token; the mode is chosen by the shape of the value, never by anything the caller can set separately, and both refusal paths answer the same 401 body so a caller cannot learn which mode was tried. The precise reason goes to the audit row alone.

**Authorization (automation plane):** By scope, never by RBAC role. The scopes are `environments:write`, `environments:read`, `routes:read`, `certificates:read`. Each path declares the scope it requires; a path declaring none is reachable by no token at all, including one carrying every scope, so a newly added path cannot silently inherit the widest grant. A token additionally carries the hostname patterns it may claim and the backend CIDRs it may point them at.

**Network gate (automation plane):** The listener refuses to start while `automation_allowed_cidrs` is empty. A source outside the allowlist is dropped at TCP accept, before the TLS handshake, so it never sees a 401 or a 403. Behind that sit the same pre-authentication budgets the cluster enrollment listener uses (a global handshake permit, a per-source concurrency slot, a per-source attempt window), with values sized for pipeline traffic. The allowlist is re-read on each accept, so narrowing it takes effect without a restart.

**Audit:** Every automation request is recorded by the outermost layer of the automation router, whatever the outcome.

**Versioning:** Management API path prefix `/api/v1/`. Version bump only on breaking changes. Non-breaking additions (new fields, new endpoints) don't require version bump.

## API Endpoints

Everything below is the v1.0 planning subset of the **management plane**.
The automation plane is a separate surface under `/automation/v1/`, and
its live shape is `lorica-api/openapi-automation.yaml`:

- `GET /automation/v1/whoami` (`environments:read`) - what the presented credential is. Reaches nothing else, so it is the call an automation makes to check that its credential is still live and still carries the scopes it expects.
- `GET /automation/v1/environments` (`environments:read`) - list the environments this token owns.
- `GET /automation/v1/environments/{name}` (`environments:read`)
- `PUT /automation/v1/environments/{name}` (`environments:write`) - one idempotent create-or-replace covering a route, its backends, a certificate binding and a lifetime, applied in a single transaction.
- `DELETE /automation/v1/environments/{name}` (`environments:write`) - also done by the reaper once `expires_at` has passed.

### Authentication

**POST /api/v1/auth/login**
- **Purpose:** Authenticate admin and create session
- **Request:**
```json
{
  "username": "admin",
  "password": "string"
}
```
- **Response:**
```json
{
  "must_change_password": false,
  "session_expires_at": "2026-03-28T22:00:00Z"
}
```

**PUT /api/v1/auth/password**
- **Purpose:** Change admin password (required on first login)
- **Request:**
```json
{
  "current_password": "string",
  "new_password": "string"
}
```
- **Response:**
```json
{
  "message": "Password updated"
}
```

### Routes

**GET /api/v1/routes**
- **Purpose:** List all configured routes
- **Response:**
```json
{
  "routes": [
    {
      "id": "uuid",
      "hostname": "example.com",
      "path_prefix": "/",
      "backends": ["uuid1", "uuid2"],
      "certificate_id": "uuid",
      "load_balancing": "round_robin",
      "waf_enabled": false,
      "enabled": true,
      "health_summary": {"healthy": 2, "degraded": 0, "down": 0}
    }
  ]
}
```

**POST /api/v1/routes**
- **Purpose:** Create a new route
- **Request:**
```json
{
  "hostname": "example.com",
  "path_prefix": "/",
  "backend_ids": ["uuid1"],
  "certificate_id": "uuid",
  "load_balancing": "round_robin",
}
```
- **Response:** Created route object (201)

**GET /api/v1/routes/:id**
- **Purpose:** Get route details with full backend and cert info

**PUT /api/v1/routes/:id**
- **Purpose:** Update route configuration

**DELETE /api/v1/routes/:id**
- **Purpose:** Delete route (with confirmation token to prevent accidental deletion)

### Backends

**GET /api/v1/backends**
- **Purpose:** List all backends with health status

**POST /api/v1/backends**
- **Purpose:** Add a new backend
- **Request:**
```json
{
  "address": "192.168.1.10:8080",
  "weight": 100,
  "health_check_enabled": true,
  "health_check_interval_s": 10,
  "tls_upstream": false
}
```

**GET /api/v1/backends/:id**
- **Purpose:** Get backend details including metrics

**PUT /api/v1/backends/:id**
- **Purpose:** Update backend configuration

**DELETE /api/v1/backends/:id**
- **Purpose:** Remove backend (triggers graceful drain if active connections exist)

### Certificates

**GET /api/v1/certificates**
- **Purpose:** List all certificates with expiry status

**POST /api/v1/certificates**
- **Purpose:** Upload a certificate (multipart: cert PEM + key PEM)

**GET /api/v1/certificates/:id**
- **Purpose:** Get certificate details (chain, domains, expiry)

**DELETE /api/v1/certificates/:id**
- **Purpose:** Delete certificate (blocked if routes still reference it)

### Status & System

**GET /api/v1/status**
- **Purpose:** Overall proxy status (routes count, backends health, certs expiry, uptime)

**GET /api/v1/system**
- **Purpose:** Host system metrics (CPU, RAM, disk, process metrics)

**GET /api/v1/logs**
- **Purpose:** Query access logs (params: route_id, status_code, time_from, time_to, search, limit, offset)

**GET /api/v1/metrics**
- **Purpose:** Prometheus-formatted metrics endpoint

### Configuration

**POST /api/v1/config/export**
- **Purpose:** Export full configuration as TOML
- **Response:** TOML file download

**POST /api/v1/config/import**
- **Purpose:** Import configuration from TOML (multipart upload)
- **Request:** TOML file upload
- **Response:** Preview of changes (added, modified, removed) - requires subsequent confirmation

**POST /api/v1/config/import/confirm**
- **Purpose:** Confirm and apply a previewed import
