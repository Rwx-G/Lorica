# API Design and Integration

## API Integration Strategy

**API Integration Strategy:** REST API over HTTPS on the management port. JSON request/response bodies. All state mutations go through the API - the dashboard and any future CLI are pure consumers.

**Authentication:** Session-based. Login returns an HTTP-only secure cookie. Sessions stored in-memory with configurable timeout (default: 30 minutes). Rate limiting on login endpoint (5 attempts per minute).

**Versioning:** API path prefix `/api/v1/`. Version bump only on breaking changes. Non-breaking additions (new fields, new endpoints) don't require version bump.

## API Endpoints

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
