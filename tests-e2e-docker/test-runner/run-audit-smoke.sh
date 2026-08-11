#!/usr/bin/env bash
# =============================================================================
# Lorica admin audit-log E2E smoke test (Story 8.9, IV1 + IV4).
#
# Pre-requisite: docker-compose `audit` profile is up. The lorica data
# volume is mounted into this runner at /lorica-data (READ-WRITE) so
# the tamper step (IV4) can mutate a row directly in access-log.db with
# sqlite3 - reproducing on-disk tampering the hash chain must detect.
#
# Covers:
#   IV1 - a real mutation (route.create / route.delete through the HTTP
#         handler) produces an audit row visible via GET /api/v1/audit
#         with the right operator/action/target, and its chain verifies.
#   IV4 - after N mutations, /audit/verify returns verified=true; after
#         tampering with a middle row's target_id in SQLite, verify
#         returns verified=false + first_break_id + chain_hash_mismatch.
#   RBAC - /audit is Operator+ (viewer 403), /audit/verify is
#          SuperAdmin-only (operator 403).
# =============================================================================
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

API="${LORICA_API}"
BACKEND1="${BACKEND1_ADDR}"
AUDIT_DB="${AUDIT_DB_PATH:-/lorica-data/access-log.db}"

log "=== audit smoke: preflight ==="
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
curl -s -o "$LOGIN_BODY" -D "$LOGIN_HEADERS" \
    "$API/api/v1/auth/login" -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PW}\"}" >/dev/null
SESSION=$(grep -i 'Set-Cookie:' "$LOGIN_HEADERS" | grep -o 'lorica_session=[^;]*' | head -1)
[ -n "$SESSION" ] || { fail "no session cookie"; exit 1; }
MUST_CHANGE=$(jq -r '.data.must_change_password // false' "$LOGIN_BODY")
if [ "$MUST_CHANGE" = "true" ]; then
    NEW_PW="AuditSmokePassword!42"
    CHANGE_JSON=$(jq -nc --arg cur "$ADMIN_PW" --arg new "$NEW_PW" \
        '{"current_password":$cur,"new_password":$new}')
    curl -s -o /dev/null -b "$SESSION" "$API/api/v1/auth/password" -X PUT \
        -H "Content-Type: application/json" -d "$CHANGE_JSON"
    ADMIN_PW="$NEW_PW"
    SESSION=$(login_as admin "$ADMIN_PW")
fi
rm -f "$LOGIN_HEADERS" "$LOGIN_BODY"
ok "admin logged in"

# --- IV1: a real mutation produces a correct audit row -------------------
log "=== audit smoke: IV1 mutation -> audit row ==="
CREATE=$(api_post "/api/v1/routes" \
    '{"hostname":"audit-iv1.example.com","path_prefix":"/","load_balancing":"round_robin"}')
ROUTE_ID=$(echo "$CREATE" | jq -r '.data.id')
[ -n "$ROUTE_ID" ] && [ "$ROUTE_ID" != "null" ] || { fail "route create returned no id"; exit 1; }
ok "route created ($ROUTE_ID)"

assert_status DELETE "$API/api/v1/routes/$ROUTE_ID" 200 "route deleted"

# The delete row is visible and attributed to admin.
DEL_AUDIT=$(api_get "/api/v1/audit?action=route.delete&limit=10")
assert_json "$DEL_AUDIT" '.data.entries[0].operator_username' "admin" "route.delete attributed to admin"
assert_json "$DEL_AUDIT" '.data.entries[0].action' "route.delete" "route.delete action recorded"
assert_json "$DEL_AUDIT" '.data.entries[0].target_id' "$ROUTE_ID" "route.delete target_id matches"
assert_json "$DEL_AUDIT" '.data.entries[0].operator_role' "super_admin" "operator_role recorded"

# The create row is filterable too.
CREATE_AUDIT=$(api_get "/api/v1/audit?action=route.create&operator=admin&limit=5")
assert_json_gt "$CREATE_AUDIT" '.data.total' 0 "route.create rows returned for operator=admin filter"

# --- IV4: verify passes on the honest chain ------------------------------
log "=== audit smoke: IV4 chain verify ==="
# Generate more mutations so the chain has depth.
for n in $(seq 1 5); do
    RID=$(api_post "/api/v1/routes" \
        "{\"hostname\":\"audit-fill-$n.example.com\",\"path_prefix\":\"/\",\"load_balancing\":\"round_robin\"}" \
        | jq -r '.data.id')
    api_del "/api/v1/routes/$RID" >/dev/null
done
VERIFY=$(api_get "/api/v1/audit/verify")
assert_json "$VERIFY" '.data.verified' "true" "honest chain verifies"
assert_json_gt "$VERIFY" '.data.total_rows' 5 "verify walked the full chain"

# --- IV4: tamper a middle row, verify localises the break ----------------
log "=== audit smoke: IV4 tamper detection ==="
if [ ! -w "$AUDIT_DB" ]; then
    fail "audit DB not writable at $AUDIT_DB (mount lorica data volume rw)"
    exit 1
fi
# Pick a row that is NOT the newest (so a successor exists to break).
MID_ID=$(sqlite3 "$AUDIT_DB" "SELECT id FROM audit_log ORDER BY id ASC LIMIT 1 OFFSET 2;")
[ -n "$MID_ID" ] || { fail "could not select a mid audit row"; exit 1; }
sqlite3 "$AUDIT_DB" "UPDATE audit_log SET target_id='tampered-999' WHERE id=$MID_ID;"
ok "tampered audit row id=$MID_ID in SQLite"

VERIFY_BROKEN=$(api_get "/api/v1/audit/verify")
assert_json "$VERIFY_BROKEN" '.data.verified' "false" "verify detects tampering"
assert_json "$VERIFY_BROKEN" '.data.first_break_id' "$MID_ID" "verify localises the earliest broken row"
assert_json "$VERIFY_BROKEN" '.data.first_break_reason' "chain_hash_mismatch" "break reason is chain_hash_mismatch"

# --- RBAC: audit-read floor is Operator+, verify is SuperAdmin ------------
log "=== audit smoke: RBAC floors ==="
OP_PW="AuditOperator!4242"
VIEW_PW="AuditViewer!424242"
api_post "/api/v1/users" "{\"username\":\"auditop\",\"password\":\"$OP_PW\",\"role\":\"operator\"}" >/dev/null
api_post "/api/v1/users" "{\"username\":\"auditview\",\"password\":\"$VIEW_PW\",\"role\":\"viewer\"}" >/dev/null

OP_SESSION=$(login_as auditop "$OP_PW")
VIEW_SESSION=$(login_as auditview "$VIEW_PW")

SESSION="$OP_SESSION"
assert_status GET "$API/api/v1/audit?limit=5" 200 "operator can read the audit log"
assert_status GET "$API/api/v1/audit/verify" 403 "operator cannot verify the chain"

SESSION="$VIEW_SESSION"
assert_status GET "$API/api/v1/audit?limit=5" 403 "viewer cannot read the audit log"

print_results
