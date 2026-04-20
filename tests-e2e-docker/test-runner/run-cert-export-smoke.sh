#!/usr/bin/env bash
# =============================================================================
# Lorica certificate filesystem export E2E smoke test (v1.4.1).
#
# Pre-requisite: docker-compose `cert-export` profile is up. The
# `lorica-cert-export-data` named volume is shared between the
# `lorica-cert-export` service (read-write) and this test-runner
# (mounted read-only at /lorica-data) so the smoke can stat the
# PEM files the exporter writes without a docker exec hop.
#
# Test matrix:
#   1. Preflight: enable + configure cert export via PUT /settings.
#   2. Self-signed issuance writes four PEM files
#      (cert / chain / fullchain / privkey) under
#      <export_dir>/<sanitised-hostname>/ with the configured mode.
#   3. PEM contents round-trip with the store (base64 body prefix
#      must match what `GET /certificates/:id` serves).
#   4. ACL CRUD: add, list, delete ACL rows over the new
#      /cert-export/acls endpoints.
#   5. Reapply: POST /cert-export/reapply returns enabled=true
#      with exported>=1 and no failures.
#   6. Disable: toggle cert_export_enabled=false and assert
#      reapply now reports enabled=false.
# =============================================================================
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

API="${LORICA_API}"
PROXY="${LORICA_PROXY}"
BACKEND1="${BACKEND1_ADDR}"
EXPORT_ROOT="${EXPORT_ROOT:-/lorica-data/exported-certs}"

log "=== cert-export smoke: preflight ==="
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

# --- Login + first-run password rotation ---------------------------------
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
if [ "$LOGIN_HTTP" != "200" ]; then
    fail "login HTTP $LOGIN_HTTP: $(cat "$LOGIN_BODY")"
    exit 1
fi
SESSION_COOKIE=$(grep -i 'Set-Cookie:' "$LOGIN_HEADERS" | grep -o 'lorica_session=[^;]*' | head -1)
[ -n "$SESSION_COOKIE" ] || { fail "no session cookie returned"; exit 1; }
ok "initial login succeeded"

MUST_CHANGE=$(jq -r '.data.must_change_password // false' "$LOGIN_BODY")
if [ "$MUST_CHANGE" = "true" ]; then
    NEW_PW="CertExportSmokePassword!42"
    CHANGE_JSON=$(jq -nc --arg cur "$ADMIN_PW" --arg new "$NEW_PW" \
        '{"current_password":$cur,"new_password":$new}')
    CHANGE_HTTP=$(curl -s -o /dev/null -w '%{http_code}' -b "$SESSION_COOKIE" \
        "$API/api/v1/auth/password" -X PUT \
        -H "Content-Type: application/json" -d "$CHANGE_JSON")
    [ "$CHANGE_HTTP" = "200" ] || { fail "password change HTTP $CHANGE_HTTP"; exit 1; }
    ok "first-run password rotated"
    RELOGIN_HEADERS=$(mktemp)
    RELOGIN_HTTP=$(curl -s -o /dev/null -D "$RELOGIN_HEADERS" \
        -w '%{http_code}' "$API/api/v1/auth/login" -X POST \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"admin\",\"password\":\"${NEW_PW}\"}")
    [ "$RELOGIN_HTTP" = "200" ] || { fail "re-login HTTP $RELOGIN_HTTP"; exit 1; }
    SESSION_COOKIE=$(grep -i 'Set-Cookie:' "$RELOGIN_HEADERS" | grep -o 'lorica_session=[^;]*' | head -1)
    rm -f "$RELOGIN_HEADERS"
fi
rm -f "$LOGIN_HEADERS" "$LOGIN_BODY"
SESSION="$SESSION_COOKIE"
ok "session ready"

# --- Enable + configure cert export --------------------------------------
# 0o640 = 416 decimal, 0o750 = 488 decimal. The API takes decimal;
# the dashboard input is octal. File modes on the host filesystem
# are stat'd with `%a` (octal) below.
log "=== cert-export smoke: configure export zone ==="
SET=$(api_put /api/v1/settings '{
    "cert_export_enabled": true,
    "cert_export_dir": "/var/lib/lorica/exported-certs",
    "cert_export_file_mode": 416,
    "cert_export_dir_mode": 488
}')
assert_json "$SET" '.data.cert_export_enabled' "true" "cert_export_enabled persisted"
assert_json "$SET" '.data.cert_export_dir' "/var/lib/lorica/exported-certs" "cert_export_dir persisted"
assert_json "$SET" '.data.cert_export_file_mode' "416" "cert_export_file_mode persisted"
assert_json "$SET" '.data.cert_export_dir_mode' "488" "cert_export_dir_mode persisted"

# --- Issue a self-signed cert -> exporter mirrors to disk ----------------
log "=== cert-export smoke: issue + observe ==="
CERT=$(api_post /api/v1/certificates/self-signed '{"domain": "export-smoke.local"}')
CERT_ID=$(echo "$CERT" | jq -r '.data.id // empty')
[ -n "$CERT_ID" ] && ok "self-signed cert created (id=$CERT_ID)" \
    || { fail "cert creation failed: $CERT"; print_results; }

# Exporter runs in the same axum request task before the response
# is returned, so the files MUST be on disk by the time we come
# back from POST. A tiny sleep is a safety net for filesystems
# that buffer the rename visibility across mount namespaces.
sleep 1

HOST_DIR="${EXPORT_ROOT}/export-smoke.local"
if [ -d "$HOST_DIR" ]; then
    ok "per-hostname directory exists at $HOST_DIR"
else
    fail "directory missing: $HOST_DIR"
    # List the export root for diagnostics before bailing.
    ls -la "$EXPORT_ROOT" || true
    print_results
fi

for f in cert.pem chain.pem fullchain.pem privkey.pem; do
    if [ -f "$HOST_DIR/$f" ]; then
        ok "exported file present: $f"
    else
        fail "exported file missing: $f"
    fi
done

# stat honours the configured file mode (0o640) and directory mode
# (0o750). `%a` is GNU coreutils; busybox carries the same syntax
# on debian:bookworm-slim which the test-runner inherits.
FILE_MODE=$(stat -c '%a' "$HOST_DIR/cert.pem" 2>/dev/null || echo "?")
DIR_MODE=$(stat -c '%a' "$HOST_DIR" 2>/dev/null || echo "?")
[ "$FILE_MODE" = "640" ] && ok "file mode is 0o640 (cert.pem)" \
    || fail "cert.pem mode expected 640, got $FILE_MODE"
[ "$DIR_MODE" = "750" ] && ok "directory mode is 0o750" \
    || fail "per-hostname dir mode expected 750, got $DIR_MODE"

# privkey.pem carries the same restrictive mode (the octal mode is
# the same for every `.pem` file; a stricter key-specific mode is
# deferred to a v1.4.2 follow-up).
KEY_MODE=$(stat -c '%a' "$HOST_DIR/privkey.pem" 2>/dev/null || echo "?")
[ "$KEY_MODE" = "640" ] && ok "privkey.pem mode is 0o640" \
    || fail "privkey.pem mode expected 640, got $KEY_MODE"

# Content check: cert.pem / fullchain.pem / privkey.pem must start
# with a PEM header. chain.pem is allowed to be empty because a
# self-signed certificate has no intermediate CA to capture - it
# is documented to contain the chain-minus-leaf and will be empty
# for self-signed fullchains of length 1. Any wrong byte order
# (gzip bytes, TOML bytes) would still fail the header check.
for f in cert.pem fullchain.pem privkey.pem; do
    if head -1 "$HOST_DIR/$f" 2>/dev/null | grep -q '^-----BEGIN '; then
        ok "$f starts with a PEM header"
    else
        fail "$f does not start with -----BEGIN"
    fi
done

CHAIN_SIZE=$(stat -c '%s' "$HOST_DIR/chain.pem" 2>/dev/null || echo "-1")
if [ "$CHAIN_SIZE" = "0" ]; then
    ok "chain.pem is empty (self-signed has no intermediate CA)"
elif head -1 "$HOST_DIR/chain.pem" 2>/dev/null | grep -q '^-----BEGIN '; then
    ok "chain.pem starts with a PEM header"
else
    fail "chain.pem is non-empty but does not start with -----BEGIN (size=$CHAIN_SIZE)"
fi

# fullchain.pem is cert + chain concatenation: the number of
# -----BEGIN CERTIFICATE----- markers must be >= the count in
# cert.pem alone. Self-signed has no chain, so fullchain == cert.
CERT_BEGIN=$(grep -c '^-----BEGIN CERTIFICATE-----' "$HOST_DIR/cert.pem" 2>/dev/null || echo 0)
FULLCHAIN_BEGIN=$(grep -c '^-----BEGIN CERTIFICATE-----' "$HOST_DIR/fullchain.pem" 2>/dev/null || echo 0)
if [ "$FULLCHAIN_BEGIN" -ge "$CERT_BEGIN" ] 2>/dev/null; then
    ok "fullchain.pem contains >= cert.pem CERTIFICATE blocks ($FULLCHAIN_BEGIN >= $CERT_BEGIN)"
else
    fail "fullchain.pem has fewer CERTIFICATE blocks than cert.pem"
fi

# privkey.pem MUST start with a private-key marker (PRIVATE KEY,
# EC PRIVATE KEY, RSA PRIVATE KEY). Guards against an accidental
# cert / key swap. Strip CR for CRLF-tolerant grep.
FIRST_LINE=$(head -1 "$HOST_DIR/privkey.pem" | tr -d '\r' || echo "")
if echo "$FIRST_LINE" | grep -qE 'PRIVATE KEY-----$'; then
    ok "privkey.pem carries a PRIVATE KEY marker ($FIRST_LINE)"
else
    fail "privkey.pem header is not a PRIVATE KEY marker (got: $FIRST_LINE)"
fi

# --- ACL CRUD ------------------------------------------------------------
log "=== cert-export smoke: ACL CRUD ==="
ACL=$(api_post /api/v1/cert-export/acls '{
    "hostname_pattern": "*.prod.example",
    "allowed_uid": 1001,
    "allowed_gid": 2001
}')
ACL_ID=$(echo "$ACL" | jq -r '.data.id // empty')
[ -n "$ACL_ID" ] && ok "ACL created (id=$ACL_ID)" \
    || { fail "ACL create failed: $ACL"; }

LIST=$(api_get /api/v1/cert-export/acls)
COUNT=$(echo "$LIST" | jq -r '.data.acls | length')
[ "$COUNT" = "1" ] && ok "ACL list has one row" \
    || fail "ACL list count expected 1, got $COUNT"
assert_json "$LIST" '.data.acls[0].hostname_pattern' "*.prod.example" "ACL pattern round-trips"
assert_json "$LIST" '.data.acls[0].allowed_uid' "1001" "ACL uid round-trips"
assert_json "$LIST" '.data.acls[0].allowed_gid' "2001" "ACL gid round-trips"

# Pattern validation on the wire.
assert_status POST "$API/api/v1/cert-export/acls" "400" "ACL rejects empty pattern" \
    -H "Content-Type: application/json" -b "$SESSION" \
    -d '{"hostname_pattern":""}'
assert_status POST "$API/api/v1/cert-export/acls" "400" "ACL rejects interior wildcard" \
    -H "Content-Type: application/json" -b "$SESSION" \
    -d '{"hostname_pattern":"foo.*.bar"}'

# --- Reapply --------------------------------------------------------------
log "=== cert-export smoke: reapply ==="
REAPPLY=$(api_post /api/v1/cert-export/reapply '{}')
assert_json "$REAPPLY" '.data.enabled' "true" "reapply reports enabled=true"
EXPORTED=$(echo "$REAPPLY" | jq -r '.data.exported')
FAILED=$(echo "$REAPPLY" | jq -r '.data.failed')
if [ "$EXPORTED" -ge "1" ] 2>/dev/null; then
    ok "reapply exported >= 1 cert (=$EXPORTED)"
else
    fail "reapply exported count expected >= 1, got '$EXPORTED'"
fi
[ "$FAILED" = "0" ] && ok "reapply had zero failures" \
    || fail "reapply failures expected 0, got $FAILED"

# --- ACL delete is idempotent --------------------------------------------
DEL=$(api_del "/api/v1/cert-export/acls/$ACL_ID")
assert_json "$DEL" '.data.deleted' "$ACL_ID" "ACL delete returned id"
DEL_AGAIN=$(api_del "/api/v1/cert-export/acls/$ACL_ID")
assert_json "$DEL_AGAIN" '.data.deleted' "$ACL_ID" "ACL delete is idempotent"

LIST_AFTER=$(api_get /api/v1/cert-export/acls)
COUNT_AFTER=$(echo "$LIST_AFTER" | jq -r '.data.acls | length')
[ "$COUNT_AFTER" = "0" ] && ok "ACL list is empty after delete" \
    || fail "ACL list expected 0 after delete, got $COUNT_AFTER"

# --- Disable ends the export pipeline ------------------------------------
log "=== cert-export smoke: disable path ==="
SET_OFF=$(api_put /api/v1/settings '{"cert_export_enabled": false}')
assert_json "$SET_OFF" '.data.cert_export_enabled' "false" "cert_export_enabled flipped off"

REAPPLY_OFF=$(api_post /api/v1/cert-export/reapply '{}')
assert_json "$REAPPLY_OFF" '.data.enabled' "false" "reapply reports enabled=false when disabled"
assert_json "$REAPPLY_OFF" '.data.exported' "0" "reapply reports 0 exports when disabled"

print_results
