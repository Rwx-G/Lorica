#!/usr/bin/env bash
# =============================================================================
# Lorica hot binary-upgrade E2E smoke test (Story 8.4, IV1/IV3).
#
# Pre-requisite: docker-compose `hot-upgrade` profile is up. The
# `lorica-hot-upgrade` service runs Lorica in supervisor/workers mode
# (the zero-downtime handoff only exists in supervisor mode). The
# `shared-hot-upgrade` volume is mounted read-write in both that service
# and this runner: the entrypoint publishes the running executable at
# /shared/lorica-bin, and this runner writes the test Ed25519 public key
# at /shared/upgrade-pubkey.hex (the path it configures via
# `upgrade_signing_pubkey_path`).
#
# What this validates for real (no simulation):
#   IV1  zero dropped/refused connections and zero 5xx through the proxy
#        across the live binary swap (sustained traffic during handoff).
#   IV3  GET /api/v1/system reports a DIFFERENT proxy.pid after the swap
#        (the replacement supervisor took over).
#   ok   lorica_hot_upgrade_total{outcome="ok"} ticked on the staging.
#   IV2  a binary signed with the WRONG key is rejected 400 and the
#        running binary is unaffected (no swap, pid unchanged), and
#        lorica_hot_upgrade_total{outcome="signature_failed"} ticked.
#
# Honest scoping note on the "ok" counter: Prometheus counters are
# per-process and in-memory. The "ok" outcome is recorded by the API
# handler in the OLD supervisor at verify+stage time, before the swap.
# Once the OLD process exits, the NEW supervisor serves /metrics from a
# fresh registry (ok=0). The assertion therefore reads the counter
# during the overlap window (the OLD process is the sole mgmt server
# until the NEW API binds), which is exactly the process that performed
# the stage. This is real, not faked; it just cannot be observed after
# the OLD process is gone. See the report for details.
# =============================================================================
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

API="${LORICA_API}"
PROXY="${LORICA_PROXY}"
BACKEND1="${BACKEND1_ADDR}"

PUBKEY_HEX_PATH="/shared/upgrade-pubkey.hex"   # path as BOTH containers see it
LORICA_BIN="/shared/lorica-bin"                # published by the entrypoint
PROXY_HOST="hot-upgrade.local"

# -------------------------------------------------------------------------
# Preflight: backend + API + published binary
# -------------------------------------------------------------------------
log "=== hot-upgrade smoke: preflight ==="
for i in $(seq 1 30); do
    curl -sf "http://$BACKEND1/healthz" >/dev/null 2>&1 && break
    sleep 1
done
ok "backend1 reachable"

for i in $(seq 1 120); do
    HTTP_CODE=$(curl -s -o /dev/null -w '%{http_code}' "$API/" 2>/dev/null || true)
    [ "$HTTP_CODE" != "000" ] && [ -n "$HTTP_CODE" ] && break
    sleep 2
done
log "Lorica API reachable (HTTP $HTTP_CODE)"

for i in $(seq 1 60); do
    [ -s "$LORICA_BIN" ] && break
    sleep 1
done
[ -s "$LORICA_BIN" ] && ok "published lorica binary present ($(stat -c '%s' "$LORICA_BIN") bytes)" \
    || { fail "published binary missing at $LORICA_BIN"; print_results; }

# -------------------------------------------------------------------------
# Login + first-run password rotation
# -------------------------------------------------------------------------
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
    NEW_PW="HotUpgradeSmokePassword!42"
    CHANGE_JSON=$(jq -nc --arg cur "$ADMIN_PW" --arg new "$NEW_PW" \
        '{"current_password":$cur,"new_password":$new}')
    CHANGE_HTTP=$(curl -s -o /dev/null -w '%{http_code}' -b "$SESSION" \
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
    SESSION=$(grep -i 'Set-Cookie:' "$RELOGIN_HEADERS" | grep -o 'lorica_session=[^;]*' | head -1)
    rm -f "$RELOGIN_HEADERS"
fi
rm -f "$LOGIN_HEADERS" "$LOGIN_BODY"
ok "session ready"

# -------------------------------------------------------------------------
# Generate a throwaway Ed25519 keypair and drop the public key at the
# path the lorica container was seeded to read
# (upgrade_signing_pubkey_path = $PUBKEY_HEX_PATH, seeded into the config
# store by the entrypoint - the settings API does not expose that field).
# The 32-byte raw verifying key is the last 32 bytes of the DER
# SubjectPublicKeyInfo (12-byte header + 32-byte key for Ed25519). The
# upgrade handler reads the file fresh on each request, so writing it
# here (before any upload) is sufficient; the IV2 signature_failed
# assertion below confirms the key is actually wired.
# -------------------------------------------------------------------------
log "=== hot-upgrade smoke: keypair + signing-key configuration ==="
PRIV_GOOD=/tmp/hu_good.pem
PRIV_BAD=/tmp/hu_bad.pem
openssl genpkey -algorithm ed25519 -out "$PRIV_GOOD" 2>/dev/null
openssl genpkey -algorithm ed25519 -out "$PRIV_BAD" 2>/dev/null

pubkey_hex() {
    openssl pkey -in "$1" -pubout -outform DER 2>/dev/null \
        | tail -c 32 | od -An -v -tx1 | tr -d ' \n'
}
PUB_GOOD_HEX=$(pubkey_hex "$PRIV_GOOD")
[ "${#PUB_GOOD_HEX}" = "64" ] && ok "test public key derived (64 hex chars)" \
    || { fail "bad public key hex length: ${#PUB_GOOD_HEX}"; print_results; }

printf '%s' "$PUB_GOOD_HEX" > "$PUBKEY_HEX_PATH"
[ -s "$PUBKEY_HEX_PATH" ] && ok "test public key written to $PUBKEY_HEX_PATH" \
    || { fail "could not write public key to $PUBKEY_HEX_PATH"; print_results; }

# -------------------------------------------------------------------------
# Seed a backend + route so the proxy has live traffic to carry.
# -------------------------------------------------------------------------
log "=== hot-upgrade smoke: seed proxied route ==="
BACKEND=$(api_post /api/v1/backends "{
    \"name\": \"hu-backend1\",
    \"group\": \"hu\",
    \"address\": \"${BACKEND1}\",
    \"h2_upstream\": false,
    \"tls\": false
}")
BACKEND_ID=$(echo "$BACKEND" | jq -r '.data.id // empty')
[ -n "$BACKEND_ID" ] || { fail "backend create: $BACKEND"; exit 1; }
ok "backend created (id=$BACKEND_ID)"

ROUTE=$(api_post /api/v1/routes "{
    \"hostname\": \"${PROXY_HOST}\",
    \"path_prefix\": \"/\",
    \"backend_ids\": [\"${BACKEND_ID}\"],
    \"enabled\": true
}")
ROUTE_ID=$(echo "$ROUTE" | jq -r '.data.id // empty')
[ -n "$ROUTE_ID" ] || { fail "route create: $ROUTE"; exit 1; }
ok "route created (id=$ROUTE_ID, host=$PROXY_HOST)"

# Wait until the route serves 2xx before measuring anything.
proxy_code() {
    curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
        -H "Host: $PROXY_HOST" "${PROXY}/" 2>/dev/null || echo 000
}
ROUTE_UP=0
for i in $(seq 1 40); do
    c=$(proxy_code)
    case "$c" in 2*) ROUTE_UP=1; break;; esac
    sleep 1
done
[ "$ROUTE_UP" = "1" ] && ok "proxy route serving 2xx (pre-upgrade)" \
    || { fail "proxy route never served 2xx before upgrade"; print_results; }

# -------------------------------------------------------------------------
# Metrics + system helpers.
# -------------------------------------------------------------------------
hu_counter() {
    # lorica_hot_upgrade_total{outcome="<arg>"} value, or 0 if absent.
    local outcome="$1" v
    v=$(curl -sf "$API/metrics" 2>/dev/null \
        | grep "^lorica_hot_upgrade_total{" \
        | grep "outcome=\"$outcome\"" \
        | awk '{print $NF}' | head -1)
    [ -z "$v" ] && echo 0 || echo "$v"
}
system_pid() {
    api_get /api/v1/system | jq -r '.data.proxy.pid // empty' 2>/dev/null
}

OLD_PID=$(system_pid)
[ -n "$OLD_PID" ] && ok "captured running supervisor pid (proxy.pid=$OLD_PID)" \
    || { fail "could not read proxy.pid from /api/v1/system"; print_results; }

# Sign the published binary with both keys up front (Ed25519 pure mode
# needs the whole file, so -rawin reads /shared/lorica-bin directly).
sign_hex() {
    local key="$1" out=/tmp/hu_sig.bin
    openssl pkeyutl -sign -inkey "$key" -rawin -in "$LORICA_BIN" -out "$out" 2>/dev/null
    od -An -v -tx1 "$out" | tr -d ' \n'
}
SIG_GOOD=$(sign_hex "$PRIV_GOOD")
SIG_BAD=$(sign_hex "$PRIV_BAD")
[ "${#SIG_GOOD}" = "128" ] && ok "good signature is 128 hex chars (64-byte Ed25519)" \
    || { fail "good signature wrong length: ${#SIG_GOOD}"; print_results; }
[ "${#SIG_BAD}" = "128" ] && ok "wrong-key signature is 128 hex chars" \
    || fail "wrong-key signature wrong length: ${#SIG_BAD}"

upload() {
    # POST the multipart upgrade; echo the HTTP status. $1 = signature hex.
    curl -s -o /tmp/hu_resp.json -w '%{http_code}' -b "$SESSION" \
        -F "binary=@${LORICA_BIN};type=application/octet-stream" \
        -F "signature=$1" \
        "$API/api/v1/system/upgrade" 2>/dev/null || echo 000
}

# =========================================================================
# IV2: wrong-key upload is rejected; running binary unaffected.
# Done first, against the live (single) supervisor, so the
# signature_failed counter is read deterministically from that process.
# =========================================================================
log "=== hot-upgrade smoke: IV2 wrong-key rejection ==="
SIGFAIL_BEFORE=$(hu_counter signature_failed)
BAD_CODE=$(upload "$SIG_BAD")
[ "$BAD_CODE" = "400" ] && ok "wrong-key binary rejected (HTTP 400)" \
    || fail "wrong-key upload expected 400, got $BAD_CODE: $(cat /tmp/hu_resp.json 2>/dev/null)"

SIGFAIL_AFTER=$(hu_counter signature_failed)
[ "$SIGFAIL_AFTER" -gt "$SIGFAIL_BEFORE" ] 2>/dev/null \
    && ok "lorica_hot_upgrade_total{outcome=signature_failed} ticked ($SIGFAIL_BEFORE -> $SIGFAIL_AFTER)" \
    || fail "signature_failed counter did not increment ($SIGFAIL_BEFORE -> $SIGFAIL_AFTER)"

PID_AFTER_BAD=$(system_pid)
[ "$PID_AFTER_BAD" = "$OLD_PID" ] && ok "running binary unaffected by rejected upload (pid still $OLD_PID)" \
    || fail "pid changed after a rejected upload (was $OLD_PID, now $PID_AFTER_BAD)"

# Confirm the proxy still serves 2xx after the rejected upload.
case "$(proxy_code)" in
    2*) ok "proxy still serving 2xx after rejected upload";;
    *)  fail "proxy not serving 2xx after rejected upload";;
esac

# =========================================================================
# IV1 + IV3: the real zero-downtime swap under sustained traffic.
# =========================================================================
log "=== hot-upgrade smoke: IV1/IV3 live swap under traffic ==="
OK_BEFORE=$(hu_counter ok)

# Sustained sequential traffic in the background. Every reply code is
# appended to a file; a refused/timed-out connection records 000.
TRAFFIC_LOG=/tmp/hu_traffic.log
: > "$TRAFFIC_LOG"
RUN_FLAG=/tmp/hu_run_traffic
: > "$RUN_FLAG"
(
    while [ -f "$RUN_FLAG" ]; do
        c=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
            -H "Host: $PROXY_HOST" "${PROXY}/" 2>/dev/null || echo 000)
        echo "$c" >> "$TRAFFIC_LOG"
    done
) &
TRAFFIC_BG=$!
# Let a baseline of traffic flow before triggering the swap.
sleep 2

# Trigger the swap. The handler records ok then signals the supervisor.
GOOD_CODE=$(upload "$SIG_GOOD")
[ "$GOOD_CODE" = "200" ] && ok "valid binary accepted + staged (HTTP 200)" \
    || { fail "valid upload expected 200, got $GOOD_CODE: $(cat /tmp/hu_resp.json 2>/dev/null)"; }

# Read the ok counter during the overlap window (see header note). The
# OLD process holds ok=BEFORE+1 and is the sole mgmt server until the NEW
# API binds, so a tight poll observes it deterministically.
OK_MAX="$OK_BEFORE"
for i in $(seq 1 20); do
    v=$(hu_counter ok)
    [ "$v" -gt "$OK_MAX" ] 2>/dev/null && OK_MAX="$v"
    [ "$OK_MAX" -gt "$OK_BEFORE" ] 2>/dev/null && break
    sleep 1
done
[ "$OK_MAX" -gt "$OK_BEFORE" ] 2>/dev/null \
    && ok "lorica_hot_upgrade_total{outcome=ok} ticked ($OK_BEFORE -> $OK_MAX)" \
    || fail "ok counter never observed incrementing ($OK_BEFORE -> $OK_MAX)"

# IV3: the OLD supervisor keeps serving its management API for the full
# worker-drain window (up to ~30s) before exit(0), so during the overlap
# a socat-forwarded /system poll can be answered by EITHER process. Wait
# for convergence: the pid must read as a single NEW value (!= OLD) for
# several consecutive polls, which only holds once the OLD process has
# drained and exited and the NEW one is the sole mgmt server.
NEW_PID=""
CONSEC=0
NEED_CONSEC=5
for i in $(seq 1 60); do
    p=$(system_pid)
    if [ -n "$p" ] && [ "$p" != "$OLD_PID" ]; then
        if [ "$p" = "$NEW_PID" ]; then
            CONSEC=$((CONSEC+1))
        else
            NEW_PID="$p"; CONSEC=1
        fi
        [ "$CONSEC" -ge "$NEED_CONSEC" ] && break
    else
        CONSEC=0
    fi
    sleep 1
done
[ -n "$NEW_PID" ] && ok "IV3: proxy.pid changed after swap ($OLD_PID -> $NEW_PID)" \
    || fail "IV3: proxy.pid never changed from $OLD_PID within window"
[ "$CONSEC" -ge "$NEED_CONSEC" ] \
    && ok "replacement supervisor pid converged stable ($NEED_CONSEC consecutive reads = $NEW_PID)" \
    || fail "proxy.pid did not converge to a stable replacement value (last=$NEW_PID, consec=$CONSEC)"

# Stop traffic and tally. Traffic ran across the whole overlap + drain.
rm -f "$RUN_FLAG"
wait "$TRAFFIC_BG" 2>/dev/null || true

TOTAL_REQ=$(wc -l < "$TRAFFIC_LOG" | tr -d ' ')
# Failures: connection refused/timeout (000) or any non-2xx response.
FAILED_REQ=$(grep -cvE '^2[0-9][0-9]$' "$TRAFFIC_LOG" || true)
REFUSED_REQ=$(grep -c '^000$' "$TRAFFIC_LOG" || true)
SVR_ERR=$(grep -cE '^5[0-9][0-9]$' "$TRAFFIC_LOG" || true)
log "traffic during swap: total=$TOTAL_REQ failed=$FAILED_REQ refused=$REFUSED_REQ 5xx=$SVR_ERR"

[ "$TOTAL_REQ" -gt 20 ] 2>/dev/null \
    && ok "sustained traffic carried $TOTAL_REQ requests across the swap" \
    || fail "too few requests during swap ($TOTAL_REQ); window may have missed the handoff"

[ "$REFUSED_REQ" = "0" ] \
    && ok "IV1: zero refused/timed-out connections during the swap" \
    || fail "IV1: $REFUSED_REQ refused/timed-out connections during the swap"

[ "$SVR_ERR" = "0" ] \
    && ok "IV1: zero 5xx responses during the swap" \
    || fail "IV1: $SVR_ERR 5xx responses during the swap"

[ "$FAILED_REQ" = "0" ] \
    && ok "IV1: every request during the swap returned 2xx" \
    || fail "IV1: $FAILED_REQ non-2xx responses during the swap (see codes: $(sort -u "$TRAFFIC_LOG" | tr '\n' ' '))"

# Final liveness: the replacement supervisor serves both planes.
case "$(proxy_code)" in
    2*) ok "post-swap: proxy serving 2xx on the replacement supervisor";;
    *)  fail "post-swap: proxy not serving 2xx";;
esac
POST_API=$(curl -s -o /dev/null -w '%{http_code}' -b "$SESSION" "$API/api/v1/system")
[ "$POST_API" = "200" ] && ok "post-swap: management API serving on the replacement supervisor" \
    || fail "post-swap: management API not serving (HTTP $POST_API)"

print_results
