#!/usr/bin/env bash
# =============================================================================
# Lorica multi-user RBAC E2E smoke test (Story 8.3, IV3).
#
# Pre-requisite: docker-compose `rbac` (or `rbac-workers`) profile is up.
#
# Covers: /auth/me, users CRUD (create / duplicate / weak password),
# the per-role authorization matrix (viewer read-only, operator no
# settings/users, super-admin full), session invalidation on role
# change and disable, the legacy {password}-only login shim, and the
# last-super-admin + self-delete guards. Users and sessions are
# supervisor-only state, so the workers profile runs the identical
# script - it proves the management API is mode-independent.
# =============================================================================
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

API="${LORICA_API}"
BACKEND1="${BACKEND1_ADDR}"

log "=== rbac smoke: preflight ==="
for i in $(seq 1 30); do
    curl -sf "http://$BACKEND1/healthz" >/dev/null 2>&1 && break
    sleep 1
done
log "backend1 ready"

for i in $(seq 1 120); do
    HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$API/" 2>/dev/null || true)
    [ "$HTTP_CODE" != "000" ] && [ -n "$HTTP_CODE" ] && break
    sleep 2
done
log "Lorica API ready"

# --- Login helpers (cookie-string based, mirrors run-ai-bot-smoke.sh) ----
# login_as <username> <password> -> echoes "lorica_session=..." or "".
login_as() {
    local username="$1" password="$2"
    local headers
    headers=$(mktemp)
    local http
    http=$(curl -s -o /dev/null -D "$headers" -w '%{http_code}' \
        "$API/api/v1/auth/login" -X POST \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$username\",\"password\":\"$password\"}")
    if [ "$http" = "200" ]; then
        grep -i 'Set-Cookie:' "$headers" | grep -o 'lorica_session=[^;]*' | head -1
    fi
    rm -f "$headers"
}

# --- Admin login + first-run password rotation ---------------------------
ADMIN_PW=""
for i in $(seq 1 60); do
    if [ -f /shared/admin_password ]; then
        ADMIN_PW=$(tr -d '[:space:]' < /shared/admin_password)
        break
    fi
    sleep 1
done
[ -n "$ADMIN_PW" ] || { fail "no admin password"; exit 1; }

LOGIN_HEADERS=$(mktemp)
LOGIN_BODY=$(mktemp)
LOGIN_HTTP=$(curl -s -o "$LOGIN_BODY" -D "$LOGIN_HEADERS" \
    -w '%{http_code}' "$API/api/v1/auth/login" -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PW}\"}")
[ "$LOGIN_HTTP" = "200" ] || { fail "login HTTP $LOGIN_HTTP: $(cat "$LOGIN_BODY")"; exit 1; }
SESSION=$(grep -i 'Set-Cookie:' "$LOGIN_HEADERS" | grep -o 'lorica_session=[^;]*' | head -1)
[ -n "$SESSION" ] || { fail "no session cookie returned"; exit 1; }
ok "initial login succeeded"

MUST_CHANGE=$(jq -r '.data.must_change_password // false' "$LOGIN_BODY")
if [ "$MUST_CHANGE" = "true" ]; then
    NEW_PW="RbacSmokePassword!42"
    CHANGE_JSON=$(jq -nc --arg cur "$ADMIN_PW" --arg new "$NEW_PW" \
        '{"current_password":$cur,"new_password":$new}')
    CHANGE_HTTP=$(curl -s -o /dev/null -w '%{http_code}' -b "$SESSION" \
        "$API/api/v1/auth/password" -X PUT \
        -H "Content-Type: application/json" -d "$CHANGE_JSON")
    [ "$CHANGE_HTTP" = "200" ] || { fail "password change HTTP $CHANGE_HTTP"; exit 1; }
    ok "first-run password rotated"
    ADMIN_PW="$NEW_PW"
    SESSION=$(login_as admin "$ADMIN_PW")
    [ -n "$SESSION" ] || { fail "re-login after rotation failed"; exit 1; }
fi
rm -f "$LOGIN_HEADERS" "$LOGIN_BODY"
ADMIN_SESSION="$SESSION"

# --- 1. Identity endpoint + legacy login shim ----------------------------
log "=== rbac smoke: identity + legacy shim ==="
ME_JSON=$(api_get "/api/v1/auth/me")
assert_json "$ME_JSON" '.data.username' "admin" "auth/me returns admin"
assert_json "$ME_JSON" '.data.role' "super_admin" "auth/me returns super_admin role"

LEGACY_HTTP=$(curl -s -o /dev/null -w '%{http_code}' \
    "$API/api/v1/auth/login" -X POST -H "Content-Type: application/json" \
    -d "{\"password\":\"${ADMIN_PW}\"}")
if [ "$LEGACY_HTTP" = "200" ]; then
    ok "legacy {password}-only login shim routes to admin (HTTP 200)"
else
    fail "legacy login shim (expected 200, got $LEGACY_HTTP)"
fi

# --- 2. Users CRUD as super admin ----------------------------------------
log "=== rbac smoke: users CRUD ==="
OP_PW="OperatorSmoke!4242"
VIEW_PW="ViewerSmoke!424242"

CREATE_OP=$(api_post "/api/v1/users" "{\"username\":\"op1\",\"password\":\"$OP_PW\",\"role\":\"operator\"}")
assert_json "$CREATE_OP" '.data.role' "operator" "operator account created"
OP_ID=$(echo "$CREATE_OP" | jq -r '.data.id')

CREATE_VIEW=$(api_post "/api/v1/users" "{\"username\":\"view1\",\"password\":\"$VIEW_PW\",\"role\":\"viewer\"}")
assert_json "$CREATE_VIEW" '.data.role' "viewer" "viewer account created"
VIEW_ID=$(echo "$CREATE_VIEW" | jq -r '.data.id')

assert_status POST "$API/api/v1/users" 409 "duplicate username rejected (409)" \
    -H "Content-Type: application/json" -d "{\"username\":\"op1\",\"password\":\"$OP_PW\",\"role\":\"viewer\"}"

assert_status POST "$API/api/v1/users" 400 "weak password rejected (400)" \
    -H "Content-Type: application/json" -d '{"username":"weak1","password":"short","role":"viewer"}'

LIST_JSON=$(api_get "/api/v1/users")
USER_COUNT=$(echo "$LIST_JSON" | jq -r '.data | length')
if [ "$USER_COUNT" = "3" ]; then
    ok "user list shows 3 accounts"
else
    fail "user list (expected 3 accounts, got $USER_COUNT)"
fi
if echo "$LIST_JSON" | jq -e '.data[] | select(.password_hash)' >/dev/null 2>&1; then
    fail "password_hash leaked in user list"
else
    ok "password_hash absent from user list"
fi

# --- 3. Operator matrix ---------------------------------------------------
log "=== rbac smoke: operator role matrix ==="
OP_SESSION=$(login_as op1 "$OP_PW")
[ -n "$OP_SESSION" ] || { fail "operator login failed"; exit 1; }

SESSION="$OP_SESSION"
OP_ME=$(api_get "/api/v1/auth/me")
assert_json "$OP_ME" '.data.role' "operator" "operator auth/me role"

assert_status POST "$API/api/v1/routes" 201 "operator can create a route" \
    -H "Content-Type: application/json" \
    -d '{"hostname":"rbac-op.example.com","path_prefix":"/","load_balancing":"round_robin"}'
assert_status GET "$API/api/v1/settings" 200 "operator can read settings"
assert_status PUT "$API/api/v1/settings" 403 "operator cannot write settings" \
    -H "Content-Type: application/json" -d '{}'
assert_status GET "$API/api/v1/users" 403 "operator cannot list users"
assert_status POST "$API/api/v1/users" 403 "operator cannot create users" \
    -H "Content-Type: application/json" -d '{"username":"nope","password":"Whatever-Pass-42!","role":"viewer"}'

# --- 4. Viewer matrix -----------------------------------------------------
log "=== rbac smoke: viewer role matrix ==="
VIEW_SESSION=$(login_as view1 "$VIEW_PW")
[ -n "$VIEW_SESSION" ] || { fail "viewer login failed"; exit 1; }

SESSION="$VIEW_SESSION"
VIEW_ME=$(api_get "/api/v1/auth/me")
assert_json "$VIEW_ME" '.data.role' "viewer" "viewer auth/me role"

assert_status GET "$API/api/v1/routes" 200 "viewer can read routes"
assert_status GET "$API/api/v1/status" 200 "viewer can read status"
assert_status POST "$API/api/v1/routes" 403 "viewer cannot create a route" \
    -H "Content-Type: application/json" \
    -d '{"hostname":"rbac-view.example.com","path_prefix":"/","load_balancing":"round_robin"}'
assert_status GET "$API/api/v1/users" 403 "viewer cannot list users"
assert_status POST "$API/api/v1/config/export" 403 "viewer cannot export config"
assert_status GET "$API/api/v1/certificates/any-id/download?format=key" 403 \
    "viewer blocked from certificate download"

# Secret scrub on the viewer-readable settings payload.
SETTINGS_JSON=$(api_get "/api/v1/settings")
HMAC_VALUE=$(echo "$SETTINGS_JSON" | jq -r '.data.bot_hmac_secret_hex // ""')
if [ "$HMAC_VALUE" = "**REDACTED**" ] || [ "$HMAC_VALUE" = "" ]; then
    ok "bot_hmac_secret_hex masked for viewer"
else
    fail "bot_hmac_secret_hex leaked to viewer: $HMAC_VALUE"
fi

# --- 5. Session invalidation on role change / disable ---------------------
log "=== rbac smoke: session invalidation ==="
SESSION="$ADMIN_SESSION"
assert_status PUT "$API/api/v1/users/$OP_ID" 200 "admin demotes op1 to viewer" \
    -H "Content-Type: application/json" -d '{"role":"viewer"}'

SESSION="$OP_SESSION"
assert_status GET "$API/api/v1/routes" 401 "demoted operator session is invalidated"

SESSION="$ADMIN_SESSION"
assert_status PUT "$API/api/v1/users/$VIEW_ID" 200 "admin disables view1" \
    -H "Content-Type: application/json" -d '{"disabled":true}'

SESSION="$VIEW_SESSION"
assert_status GET "$API/api/v1/routes" 401 "disabled viewer session is invalidated"

DISABLED_HTTP=$(curl -s -o /dev/null -w '%{http_code}' \
    "$API/api/v1/auth/login" -X POST -H "Content-Type: application/json" \
    -d "{\"username\":\"view1\",\"password\":\"$VIEW_PW\"}")
if [ "$DISABLED_HTTP" = "401" ]; then
    ok "disabled account cannot log in (401)"
else
    fail "disabled account login (expected 401, got $DISABLED_HTTP)"
fi

SESSION="$ADMIN_SESSION"
assert_status PUT "$API/api/v1/users/$VIEW_ID" 200 "admin re-enables view1" \
    -H "Content-Type: application/json" -d '{"disabled":false}'
REENABLED_SESSION=$(login_as view1 "$VIEW_PW")
if [ -n "$REENABLED_SESSION" ]; then
    ok "re-enabled account logs in again"
else
    fail "re-enabled account cannot log in"
fi

# --- 6. Guards ------------------------------------------------------------
log "=== rbac smoke: guards ==="
SESSION="$ADMIN_SESSION"
ADMIN_ID=$(api_get "/api/v1/users" | jq -r '.data[] | select(.username=="admin") | .id')

assert_status PUT "$API/api/v1/users/$ADMIN_ID" 400 "cannot demote the last super admin" \
    -H "Content-Type: application/json" -d '{"role":"operator"}'
assert_status PUT "$API/api/v1/users/$ADMIN_ID" 400 "cannot disable the last super admin" \
    -H "Content-Type: application/json" -d '{"disabled":true}'
assert_status DELETE "$API/api/v1/users/$ADMIN_ID" 400 "cannot delete own account"

assert_status DELETE "$API/api/v1/users/$OP_ID" 200 "admin deletes op1"
assert_status GET "$API/api/v1/users/$OP_ID" 404 "deleted account is gone"

print_results
