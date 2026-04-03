# Exposing the Lorica Dashboard Through Lorica

> **WARNING - NOT RECOMMENDED FOR PRODUCTION**
>
> Exposing the dashboard through Lorica itself creates a circular dependency:
> if Lorica crashes or restarts, you lose access to the dashboard needed to
> debug it. For production deployments, prefer SSH tunnels, a bastion host
> (Teleport, Boundary), or VPN with direct access to `localhost:9443`.

## Overview

By default, Lorica's management API listens on `http://127.0.0.1:9443`
(HTTP, localhost only). This guide shows how to make the dashboard accessible
remotely by creating a route in Lorica that proxies to its own management API.

This is useful when:

- You don't have a bastion or VPN to reach the server
- You want TLS-encrypted dashboard access from a remote browser
- You want to protect the dashboard with WAF and rate limiting

## Prerequisites

- Lorica running and accessible on `localhost:9443`
- A DNS record pointing to your server (e.g. `lorica.example.com`)
- A TLS certificate for that hostname (Let's Encrypt or manual upload)
- Admin password for the Lorica dashboard

## Security Checklist

Before proceeding, make sure you will:

- [x] **IP allowlist** - restrict to your management network CIDR
- [x] **TLS** - always use HTTPS (force_https enabled)
- [x] **WAF** - enable in blocking mode on the dashboard route
- [x] **Rate limiting** - protect login from brute force
- [x] **Fallback access** - keep `localhost:9443` available via SSH tunnel
- [x] **Disable health checks** - avoid the dashboard backend checking itself

## Common Private Network CIDRs

| Network type | CIDR | Description |
|---|---|---|
| Home / small office | `192.168.0.0/16` | Most consumer routers |
| Corporate LAN | `10.0.0.0/8` | Large private networks |
| Docker bridge | `172.16.0.0/12` | Docker default bridge networks |
| Single IP | `203.0.113.50/32` | Restrict to one specific IP |
| Multiple CIDRs | `192.168.1.0/24,10.0.0.0/8` | Comma-separated in Lorica |

## Setup via API (curl)

The dashboard UI requires an existing session, so the initial self-proxy
setup must be done via the API.

### Step 1 - Login

```bash
LORICA="http://127.0.0.1:9443"
COOKIE=$(mktemp)

curl -s -c "$COOKIE" "$LORICA/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"YOUR_PASSWORD"}'
```

### Step 2 - Create the dashboard backend

```bash
BACKEND_ID=$(curl -s -b "$COOKIE" "$LORICA/api/v1/backends" \
  -H 'Content-Type: application/json' \
  -d '{
    "address": "127.0.0.1:9443",
    "name": "lorica-dashboard",
    "tls_upstream": false,
    "health_check_enabled": false
  }' | jq -r '.data.id')

echo "Backend ID: $BACKEND_ID"
```

> **Note:** `tls_upstream: false` because the management API listens on
> plain HTTP. Health checks are disabled to avoid a self-referencing loop.

### Step 3 - Provision a TLS certificate

**Option A - Let's Encrypt (HTTP-01):**

```bash
curl -s -b "$COOKIE" "$LORICA/api/v1/acme/provision" \
  -H 'Content-Type: application/json' \
  -d '{
    "domain": "lorica.example.com",
    "contact_email": "admin@example.com",
    "staging": false
  }'
```

**Option B - Upload manually:**

```bash
curl -s -b "$COOKIE" "$LORICA/api/v1/certificates" \
  -H 'Content-Type: application/json' \
  -d '{
    "domain": "lorica.example.com",
    "cert_pem": "-----BEGIN CERTIFICATE-----\n...\n-----END CERTIFICATE-----",
    "key_pem": "-----BEGIN PRIVATE KEY-----\n...\n-----END PRIVATE KEY-----"
  }'
```

Save the certificate ID from the response:

```bash
CERT_ID="<id-from-response>"
```

### Step 4 - Create the route

Replace `ALLOWED_CIDR` with your management network (see table above).

```bash
HOSTNAME="lorica.example.com"
ALLOWED_CIDR="192.168.0.0/16"

curl -s -b "$COOKIE" "$LORICA/api/v1/routes" \
  -H 'Content-Type: application/json' \
  -d '{
    "hostname": "'"$HOSTNAME"'",
    "path_prefix": "/",
    "backends": ["'"$BACKEND_ID"'"],
    "certificate_id": "'"$CERT_ID"'",
    "enabled": true,
    "force_https": true,
    "waf_enabled": true,
    "waf_mode": "blocking",
    "rate_limit_rps": 20,
    "rate_limit_burst": 5,
    "ip_allowlist": "'"$ALLOWED_CIDR"'",
    "access_log_enabled": true
  }'
```

### Step 5 - Verify

Open `https://lorica.example.com` in your browser. You should see the
Lorica login page, served through Lorica's own proxy with TLS, WAF, and
IP filtering active.

## Automated Script

Save as `setup-dashboard-proxy.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

# ---- Configuration ----
LORICA="http://127.0.0.1:9443"
HOSTNAME="${1:?Usage: $0 <hostname> <allowed-cidr> [management-port]}"
ALLOWED_CIDR="${2:?Usage: $0 <hostname> <allowed-cidr> [management-port]}"
MGMT_PORT="${3:-9443}"
COOKIE=$(mktemp)
trap "rm -f $COOKIE" EXIT

echo "Lorica Dashboard Self-Proxy Setup"
echo "================================="
echo "Hostname:     $HOSTNAME"
echo "Allowed CIDR: $ALLOWED_CIDR"
echo "Management:   127.0.0.1:$MGMT_PORT"
echo ""

# Prompt for password (masked)
read -sp "Admin password: " PASSWORD
echo ""

# Login
echo "[1/4] Logging in..."
LOGIN=$(curl -s -c "$COOKIE" "$LORICA/api/v1/auth/login" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg p "$PASSWORD" '{username:"admin",password:$p}')")

if echo "$LOGIN" | jq -e '.error' > /dev/null 2>&1; then
  echo "ERROR: $(echo "$LOGIN" | jq -r '.error.message')"
  exit 1
fi

# Create backend
echo "[2/4] Creating dashboard backend..."
BACKEND=$(curl -s -b "$COOKIE" "$LORICA/api/v1/backends" \
  -H 'Content-Type: application/json' \
  -d "$(jq -n --arg addr "127.0.0.1:$MGMT_PORT" '{
    address: $addr,
    name: "lorica-dashboard",
    tls_upstream: false,
    health_check_enabled: false
  }')")

BACKEND_ID=$(echo "$BACKEND" | jq -r '.data.id')
if [ "$BACKEND_ID" = "null" ] || [ -z "$BACKEND_ID" ]; then
  echo "ERROR: Failed to create backend"
  echo "$BACKEND" | jq .
  exit 1
fi
echo "  Backend ID: $BACKEND_ID"

# Check for existing certificate
echo "[3/4] Looking for TLS certificate..."
CERT_ID=$(curl -s -b "$COOKIE" "$LORICA/api/v1/certificates" | \
  jq -r --arg h "$HOSTNAME" '.data.certificates[] | select(.domain == $h) | .id' | head -1)

if [ -n "$CERT_ID" ] && [ "$CERT_ID" != "null" ]; then
  echo "  Found existing certificate: $CERT_ID"
else
  echo "  No certificate found for $HOSTNAME."
  echo "  Attempting Let's Encrypt HTTP-01 provisioning..."
  read -p "  Contact email for Let's Encrypt: " ACME_EMAIL
  ACME=$(curl -s -b "$COOKIE" "$LORICA/api/v1/acme/provision" \
    -H 'Content-Type: application/json' \
    -d "$(jq -n --arg d "$HOSTNAME" --arg e "$ACME_EMAIL" '{
      domain: $d,
      contact_email: $e,
      staging: false
    }')")
  CERT_ID=$(echo "$ACME" | jq -r '.data.id // empty')
  if [ -z "$CERT_ID" ]; then
    echo "  WARNING: ACME provisioning failed. Create a certificate manually"
    echo "  and re-run, or set CERT_ID and create the route manually."
    echo "  Response: $(echo "$ACME" | jq -c .)"
    CERT_ID=""
  else
    echo "  Certificate provisioned: $CERT_ID"
  fi
fi

# Create route
echo "[4/4] Creating dashboard route..."
ROUTE_BODY=$(jq -n \
  --arg h "$HOSTNAME" \
  --arg bid "$BACKEND_ID" \
  --arg cid "$CERT_ID" \
  --arg cidr "$ALLOWED_CIDR" '{
    hostname: $h,
    path_prefix: "/",
    backends: [$bid],
    enabled: true,
    force_https: true,
    waf_enabled: true,
    waf_mode: "blocking",
    rate_limit_rps: 20,
    rate_limit_burst: 5,
    ip_allowlist: $cidr,
    access_log_enabled: true
  } + (if $cid != "" then {certificate_id: $cid} else {} end)')

ROUTE=$(curl -s -b "$COOKIE" "$LORICA/api/v1/routes" \
  -H 'Content-Type: application/json' \
  -d "$ROUTE_BODY")

ROUTE_ID=$(echo "$ROUTE" | jq -r '.data.id')
if [ "$ROUTE_ID" = "null" ] || [ -z "$ROUTE_ID" ]; then
  echo "ERROR: Failed to create route"
  echo "$ROUTE" | jq .
  exit 1
fi

echo ""
echo "Done! Dashboard accessible at: https://$HOSTNAME"
echo ""
echo "Route ID:   $ROUTE_ID"
echo "Backend ID: $BACKEND_ID"
echo "Cert ID:    ${CERT_ID:-none}"
echo ""
echo "Security:"
echo "  - WAF:          blocking mode"
echo "  - Rate limit:   20 req/s (burst 5)"
echo "  - IP allowlist: $ALLOWED_CIDR"
echo "  - HTTPS:        forced"
echo ""
echo "IMPORTANT: Always keep localhost:$MGMT_PORT as a fallback."
echo "  ssh -L $MGMT_PORT:127.0.0.1:$MGMT_PORT user@server"
```

## Removing the Self-Proxy

If you need to undo this setup:

```bash
# Delete the route and backend via the dashboard or API
curl -s -b "$COOKIE" -X DELETE "$LORICA/api/v1/routes/<route-id>"
curl -s -b "$COOKIE" -X DELETE "$LORICA/api/v1/backends/<backend-id>"
```

## Fallback Access

If Lorica is down or the self-proxy is misconfigured, use an SSH tunnel:

```bash
ssh -L 9443:127.0.0.1:9443 user@your-server
# Then open http://127.0.0.1:9443 in your browser
```

## Alternatives for Production

| Method | Security | Complexity | Dependency |
|---|---|---|---|
| **SSH tunnel** | High (encrypted, key-based) | Low | SSH access |
| **VPN** (WireGuard, OpenVPN) | High | Medium | VPN infrastructure |
| **Bastion** (Teleport, Boundary) | Very high (audit, RBAC) | High | Bastion infrastructure |
