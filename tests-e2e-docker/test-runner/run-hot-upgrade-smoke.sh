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
    v=$(curl -sf -b "$SESSION" "$API/metrics" 2>/dev/null \
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

# sd_notify emit coverage (Story 8.4 audit): bind a datagram listener on
# the same $NOTIFY_SOCKET the lorica container points at, so we can prove
# the NEW supervisor emits `READY=1` + `MAINPID=<newpid>` after the ack.
# The socket lives on the shared volume; chmod 0777 lets the unprivileged
# lorica user (different uid than this root runner) sendto it. Bound BEFORE
# the swap so the post-handoff datagram lands.
NOTIFY_SOCK=/shared/notify.sock
NOTIFY_LOG=/shared/notify.log
rm -f "$NOTIFY_SOCK" "$NOTIFY_LOG"
python3 - "$NOTIFY_SOCK" "$NOTIFY_LOG" <<'PY' &
import socket, sys, os
sock_path, out_path = sys.argv[1], sys.argv[2]
s = socket.socket(socket.AF_UNIX, socket.SOCK_DGRAM)
s.bind(sock_path)
os.chmod(sock_path, 0o777)
with open(out_path, "a") as f:
    while True:
        data, _ = s.recvfrom(4096)
        f.write(data.decode("utf-8", "replace") + "\n---\n")
        f.flush()
PY
NOTIFY_BG=$!
# Let the listener bind + chmod before any notify can be sent.
sleep 1

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

# sd_notify emit coverage: the NEW supervisor must have sent a
# `READY=1\nMAINPID=<newpid>` datagram to $NOTIFY_SOCKET after the ack.
# Give the datagram a moment to be captured, then stop the listener.
sleep 2
kill "$NOTIFY_BG" 2>/dev/null || true
if grep -q "READY=1" "$NOTIFY_LOG" 2>/dev/null; then
    ok "sd_notify READY=1 datagram captured on \$NOTIFY_SOCKET"
else
    fail "no sd_notify READY=1 datagram captured (emit path not exercised); log: $(tr '\n' ' ' < "$NOTIFY_LOG" 2>/dev/null)"
fi
if [ -n "$NEW_PID" ] && grep -q "MAINPID=$NEW_PID" "$NOTIFY_LOG" 2>/dev/null; then
    ok "sd_notify MAINPID matches the replacement supervisor pid ($NEW_PID)"
else
    fail "sd_notify MAINPID did not match new pid $NEW_PID; log: $(tr '\n' ' ' < "$NOTIFY_LOG" 2>/dev/null)"
fi

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

# =========================================================================
# Streams across a hot upgrade (Story 12.11 Lot G, delivered by Story
# 12.12 Lot K). A second upgrade of the same binary, after the first
# one's old generation has finished, with worker_drain_timeout_s at
# 120 s and three streams bound:
#
#   12.11-iv1-stream-ssh-drained-by-upgrade
#       IV1: an SSH session through a TCP stream outlives the upgrade
#       for the drain, then ends on a FIN with drained_by_upgrade in the
#       stream log, and the old generation's drain report reaches the
#       new generation's /metrics;
#   12.11-x-stream-new-connection-after-upgrade
#       a session opened at T0 + 10 s belongs to the new generation and
#       outlives the old one, and the management API answers from the
#       new binary while the old one drains;
#   12.11-x-udp-across-upgrade
#       one UDP query every 50 ms across the upgrade on a bounded
#       stream, every one answered within 1 s, no binding_draining drop;
#   12.11-x-fd-transfer-past-32
#       a 64-port TCP range and a UDP stream in the transfer table, the
#       upgrade completes, every port answers afterwards.
#
# Each prints its one L4-SCENARIO line (Story 12.12 D-c) at the end.
# Everything this section creates is named `l4k-`, and it is removed at
# the end, the drain setting restored.
# =========================================================================
log "=== hot-upgrade smoke: streams across an upgrade (Story 12.11 Lot G) ==="
# Every check below records its outcome; `-e` would end the section at
# the first failing probe and lose the scenario lines.
set +e

STREAM_HOST="${LORICA_STREAM_HOST}"
SSH_HOST="${SSH_BACKEND_HOST}"
L4_BACKENDS="${L4_BACKENDS_HOST}"
DRAIN_S=120
SSH_PORT=2222
UDP_PORT=5300
RANGE_FIRST=7400
RANGE_LAST=7463
K_IV1=12.11-iv1-stream-ssh-drained-by-upgrade
K_NEW=12.11-x-stream-new-connection-after-upgrade
K_UDP=12.11-x-udp-across-upgrade
K_FDS=12.11-x-fd-transfer-past-32
K_ALL="$K_IV1 $K_NEW $K_UDP $K_FDS"
K_DIR=/tmp/l4k
rm -rf "$K_DIR"
mkdir -p "$K_DIR"
declare -A K_FAILED=()
declare -A K_NOTE=()

k_ok() { ok "[$1] $2"; }
k_fail() {
    fail "[$1] $2"
    K_FAILED[$1]="${K_FAILED[$1]:+${K_FAILED[$1]}; }$2"
}
k_fail_all() {
    local name
    for name in $K_ALL; do k_fail "$name" "$1"; done
}
k_note() { K_NOTE[$1]="${K_NOTE[$1]:+${K_NOTE[$1]}; }$2"; }
k_line() {
    local name="$1" status=PASS detail
    detail="${K_NOTE[$name]:--}"
    if [ -n "${K_FAILED[$name]:-}" ]; then
        status=FAIL
        detail="${K_FAILED[$name]}"
    fi
    printf 'L4-SCENARIO %s %s %s\n' "$name" "$status" "$(printf '%s' "$detail" | tr '\r\n\t' '   ')"
}
k_now() { date +%s; }
k_sleep_until() {
    local wait=$(( $1 - $(k_now) ))
    [ "$wait" -gt 0 ] && sleep "$wait"
}
k_ip() {
    python3 -c 'import socket, sys; print(socket.gethostbyname(sys.argv[1]))' "$1" 2>/dev/null
}
k_metrics() { curl -sf -b "$SESSION" "$API/metrics" 2>/dev/null; }
# The value of one series, or empty: $1 family, then label="value"
# fragments every one of which the series must carry.
k_series() {
    local family="$1" lines
    shift
    lines=$(k_metrics | grep "^${family}{")
    local fragment
    for fragment in "$@"; do
        lines=$(printf '%s\n' "$lines" | grep -F "$fragment")
    done
    printf '%s\n' "$lines" | awk 'NF {print $NF}' | head -1
}
k_preview() { api_get /api/v1/system/upgrade/preview; }
k_bind_state() {
    api_get /api/v1/streams/status \
        | jq -r --arg id "$1" '[.data.streams[] | select(.id == $id) | .bind.state // "none"][0] // "absent"'
}
k_wait_bound() {
    local i
    for i in $(seq 1 50); do
        [ "$(k_bind_state "$1")" = bound ] && return 0
        sleep 0.2
    done
    return 1
}
k_backend() {
    api_post /api/v1/backends \
        "{\"name\":\"$1\",\"group\":\"l4k\",\"address\":\"$2\",\"health_check_enabled\":false}" \
        | jq -r '.data.id // empty'
}
k_stream() {
    local answer
    answer=$(api_post /api/v1/streams "$1")
    printf '%s' "$answer" | jq -r '.data.id // empty' 2>/dev/null | grep . \
        || { printf 'refused: %s' "$(printf '%s' "$answer" | head -c 300)"; return 1; }
}
# Session $1: an SSH command printing the remote clock every second,
# its stdout, stderr and exit code under $K_DIR/$1.*.
k_ssh() {
    ssh -i "$K_DIR/client_key" -p "$SSH_PORT" -o BatchMode=yes \
        -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
        -o ConnectTimeout=10 "tester@${STREAM_HOST}" \
        'while sleep 1; do date +%s; done' \
        > "$K_DIR/$1.out" 2> "$K_DIR/$1.err" < /dev/null
    echo $? > "$K_DIR/$1.code"
}
k_last_tick() { tail -n 1 "$K_DIR/$1.out" 2>/dev/null | tr -dc '0-9'; }

# Every port of the range answers as itself: port N reaches backend
# port N, whose first line names it.
K_RANGE_CHECK='
import socket, sys
host, first, last = sys.argv[1], int(sys.argv[2]), int(sys.argv[3])
bad = []
for port in range(first, last + 1):
    try:
        with socket.create_connection((host, port), timeout=3) as s:
            s.settimeout(3)
            s.sendall(b"x\n")
            got = b""
            while b"\n" not in got:
                chunk = s.recv(256)
                if not chunk:
                    break
                got += chunk
        if not got.startswith(b"name=hu-range port=%d " % port):
            bad.append("%d:%r" % (port, got[:40]))
    except OSError as e:
        bad.append("%d:%s" % (port, e))
print("ok %d" % (last - first + 1) if not bad else "bad " + " ".join(bad[:8]))
'
# One datagram echoed through the UDP stream.
K_UDP_ONCE='
import socket, sys
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.settimeout(1)
s.connect((sys.argv[1], int(sys.argv[2])))
for attempt in range(5):
    probe = b"once %d" % attempt
    try:
        s.send(probe)
        if s.recv(2048) == probe:
            print("ok")
            sys.exit(0)
    except OSError:
        pass
print("no echo in 5 tries")
sys.exit(1)
'
# One query every 50 ms from one socket for the duration, each owed its
# echo within 1 s. The socket is connected, so an answer from any other
# address than the one queried is dropped by the kernel and counts lost.
K_UDP_SERIES='
import json, socket, sys, time
host, port, duration = sys.argv[1], int(sys.argv[2]), float(sys.argv[3])
interval, timeout = 0.05, 1.0
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect((host, port))
s.setblocking(False)
sent, answered, late, errors = {}, set(), 0, 0
start = time.monotonic()
n = 0
while True:
    now = time.monotonic()
    if now - start >= duration + timeout:
        break
    if now - start < duration and now >= start + n * interval:
        sent[n] = now
        try:
            s.send(b"q %d" % n)
        except OSError:
            errors += 1
        n += 1
    try:
        while True:
            data = s.recv(2048)
            k = int(data.split()[1])
            if k in sent and k not in answered:
                if time.monotonic() - sent[k] <= timeout:
                    answered.add(k)
                else:
                    late += 1
    except (BlockingIOError, ValueError, IndexError):
        pass
    except OSError:
        errors += 1
    time.sleep(0.002)
lost = sorted(k for k in sent if k not in answered)
print(json.dumps({"sent": len(sent), "answered": len(answered), "lost": len(lost),
                  "late": late, "errors": errors, "first_lost": lost[:10]}))
'

# ---- Setup -----------------------------------------------------------
K_SETUP=ok
# The first upgrade's old generation drains until idle; this upgrade
# starts once it is gone, so the preview's previous_generation below is
# this upgrade's own.
for i in $(seq 1 120); do
    [ "$(k_preview | jq -r '.data.previous_generation')" = null ] && break
    sleep 1
done
if [ "$(k_preview | jq -r '.data.previous_generation')" = null ]; then
    ok "the first upgrade's old generation has finished its drain"
else
    k_fail_all "the first upgrade's old generation still drains after 120 s"
    K_SETUP=failed
fi
GEN2_PID=$(system_pid)

DRAIN_BEFORE=$(api_get /api/v1/settings | jq -r '.data.worker_drain_timeout_s')
api_put /api/v1/settings "{\"worker_drain_timeout_s\":${DRAIN_S}}" >/dev/null
if [ "$(api_get /api/v1/settings | jq -r '.data.worker_drain_timeout_s')" = "$DRAIN_S" ]; then
    ok "worker_drain_timeout_s set to ${DRAIN_S} (was ${DRAIN_BEFORE})"
else
    k_fail_all "worker_drain_timeout_s could not be set to ${DRAIN_S}"
    K_SETUP=failed
fi

for i in $(seq 1 60); do
    [ -s /shared/ssh-client-key ] && break
    sleep 1
done
cp /shared/ssh-client-key "$K_DIR/client_key" 2>/dev/null && chmod 0600 "$K_DIR/client_key"
[ -s "$K_DIR/client_key" ] || { k_fail_all "the ssh backend published no client key"; K_SETUP=failed; }

SSH_IP=$(k_ip "$SSH_HOST")
BACKENDS_IP=$(k_ip "$L4_BACKENDS")
SSH_BID=$(k_backend l4k-ssh "${SSH_IP}:22")
UDP_BID=$(k_backend l4k-udp-echo "${BACKENDS_IP}:${UDP_PORT}")
RANGE_BID=$(k_backend l4k-range "${BACKENDS_IP}")
if [ -n "$SSH_BID" ] && [ -n "$UDP_BID" ] && [ -n "$RANGE_BID" ]; then
    ok "backends created: ssh ${SSH_IP}:22, udp echo ${BACKENDS_IP}:${UDP_PORT}, range ${BACKENDS_IP}"
else
    k_fail_all "backend create failed (ssh='$SSH_BID' udp='$UDP_BID' range='$RANGE_BID')"
    K_SETUP=failed
fi

SSH_SID=$(k_stream "{\"name\":\"l4k-ssh\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":${SSH_PORT},\"backend_ids\":[\"${SSH_BID}\"]}") \
    || { k_fail_all "ssh stream: $SSH_SID"; K_SETUP=failed; }
# An exposed UDP listen address needs a source allowlist or an explicit
# source session cap (docs/streams.md, the listen-address rule). Setting
# `udp` keeps the default bounds, so the stream expects responses and
# its upgrade policy is relay_in_flight.
UDP_SID=$(k_stream "{\"name\":\"l4k-udp\",\"protocol\":\"udp\",\"listen_address\":\"0.0.0.0\",\"port_first\":${UDP_PORT},\"backend_ids\":[\"${UDP_BID}\"],\"udp\":{\"source_session_cap\":64}}") \
    || { k_fail_all "udp stream: $UDP_SID"; K_SETUP=failed; }
RANGE_SID=$(k_stream "{\"name\":\"l4k-range\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":${RANGE_FIRST},\"port_last\":${RANGE_LAST},\"backend_ids\":[\"${RANGE_BID}\"]}") \
    || { k_fail_all "range stream: $RANGE_SID"; K_SETUP=failed; }
for sid in "$SSH_SID" "$UDP_SID" "$RANGE_SID"; do
    [ "$K_SETUP" = ok ] || break
    if ! k_wait_bound "$sid"; then
        k_fail_all "stream $sid not bound within 10 s ($(k_bind_state "$sid"))"
        K_SETUP=failed
    fi
done

if [ "$K_SETUP" = ok ]; then
    ok "three streams bound: ssh :${SSH_PORT}, udp :${UDP_PORT}, tcp :${RANGE_FIRST}-${RANGE_LAST}"

    # ---- Before the upgrade --------------------------------------------
    RANGE_BEFORE=$(python3 -c "$K_RANGE_CHECK" "$STREAM_HOST" "$RANGE_FIRST" "$RANGE_LAST")
    [ "$RANGE_BEFORE" = "ok 64" ] \
        && k_ok "$K_FDS" "all 64 range ports answer before the upgrade" \
        || k_fail "$K_FDS" "range before the upgrade: $RANGE_BEFORE"
    UDP_BEFORE=$(python3 -c "$K_UDP_ONCE" "$STREAM_HOST" "$UDP_PORT")
    [ "$UDP_BEFORE" = ok ] \
        && k_ok "$K_UDP" "the UDP stream echoes before the upgrade" \
        || k_fail "$K_UDP" "the UDP stream before the upgrade: $UDP_BEFORE"

    k_ssh a &
    SSH_A=$!
    for i in $(seq 1 30); do
        [ "$(wc -l < "$K_DIR/a.out" 2>/dev/null || echo 0)" -ge 2 ] && break
        sleep 0.5
    done
    if [ "$(wc -l < "$K_DIR/a.out" 2>/dev/null || echo 0)" -ge 2 ]; then
        k_ok "$K_IV1" "session A prints the remote clock through the stream"
    else
        k_fail "$K_IV1" "session A never printed: $(tr '\n' ' ' < "$K_DIR/a.err" 2>/dev/null | head -c 300)"
    fi

    PREVIEW=$(k_preview)
    P_DRAIN=$(printf '%s' "$PREVIEW" | jq -r '.data.drain_timeout_s')
    P_HANDOFF=$(printf '%s' "$PREVIEW" | jq -r '.data.handoff_available')
    P_SSH=$(printf '%s' "$PREVIEW" | jq -c --arg id "$SSH_SID" '[.data.streams[] | select(.stream_id == $id) | {established, on_upgrade}][0]')
    P_UDP=$(printf '%s' "$PREVIEW" | jq -r --arg id "$UDP_SID" '[.data.streams[] | select(.stream_id == $id) | .on_upgrade][0]')
    if [ "$P_DRAIN" = "$DRAIN_S" ] && [ "$P_HANDOFF" = true ] \
        && [ "$P_SSH" = '{"established":1,"on_upgrade":"drain"}' ]; then
        k_ok "$K_IV1" "preview: drain_timeout_s=${P_DRAIN}, the ssh stream established=1 on_upgrade=drain"
    else
        k_fail "$K_IV1" "preview answered drain=${P_DRAIN} handoff=${P_HANDOFF} ssh=${P_SSH}"
    fi
    [ "$P_UDP" = relay_in_flight ] \
        && k_ok "$K_UDP" "preview: the bounded UDP stream is relay_in_flight" \
        || k_fail "$K_UDP" "preview: the UDP stream on_upgrade=${P_UDP}"

    # ---- The upgrade at T0 ---------------------------------------------
    python3 -c "$K_UDP_SERIES" "$STREAM_HOST" "$UDP_PORT" 35 > "$K_DIR/udp.json" 2>&1 &
    UDP_BG=$!
    sleep 3
    T0=$(k_now)
    UP_CODE=$(upload "$SIG_GOOD")
    if [ "$UP_CODE" = "200" ]; then
        ok "second upgrade accepted at T0=${T0} (HTTP 200)"
    else
        k_fail_all "second upgrade answered HTTP ${UP_CODE}: $(head -c 300 /tmp/hu_resp.json 2>/dev/null)"
    fi

    GEN3_PID=""
    for i in $(seq 1 40); do
        p=$(system_pid)
        if [ -n "$p" ] && [ "$p" != "$GEN2_PID" ]; then
            GEN3_PID="$p"
            break
        fi
        sleep 0.25
    done
    HANDOFF_S=$(( $(k_now) - T0 ))
    if [ -n "$GEN3_PID" ]; then
        ok "the management API answers from the new supervisor ${GEN3_PID} ${HANDOFF_S} s after T0"
    else
        k_fail_all "proxy.pid still ${GEN2_PID} 10 s after T0"
    fi

    k_sleep_until $(( T0 + 10 ))
    k_ssh b &
    SSH_B=$!

    k_sleep_until $(( T0 + 15 ))
    DURING_PREVIOUS=$(k_preview | jq -r '.data.previous_generation.pid // empty')
    DURING_PID=$(system_pid)
    if [ -n "$GEN3_PID" ] && [ "$DURING_PID" = "$GEN3_PID" ] && [ "$DURING_PREVIOUS" = "$GEN2_PID" ]; then
        k_ok "$K_NEW" "at T0+15 s the API answers from ${GEN3_PID} while the preview names ${GEN2_PID} as draining"
        k_note "$K_NEW" "API during the drain answered by the new supervisor ${GEN3_PID}, preview naming ${GEN2_PID} as the previous generation"
    else
        k_fail "$K_NEW" "at T0+15 s system pid=${DURING_PID} previous_generation=${DURING_PREVIOUS} (old ${GEN2_PID}, new ${GEN3_PID})"
    fi

    # ---- The fd transfer: every port of both streams, new generation ---
    RANGE_AFTER=$(python3 -c "$K_RANGE_CHECK" "$STREAM_HOST" "$RANGE_FIRST" "$RANGE_LAST")
    UDP_AFTER=$(python3 -c "$K_UDP_ONCE" "$STREAM_HOST" "$UDP_PORT")
    if [ "$RANGE_AFTER" = "ok 64" ] && [ "$UDP_AFTER" = ok ] && [ -n "$GEN3_PID" ]; then
        k_ok "$K_FDS" "after the upgrade all 64 range ports and the UDP stream answer"
    else
        k_fail "$K_FDS" "after the upgrade: range '${RANGE_AFTER}', udp '${UDP_AFTER}'"
    fi
    COMPLETED=$(hu_counter completed)
    if [ "$COMPLETED" = "1" ]; then
        k_ok "$K_FDS" "the new generation recorded lorica_hot_upgrade_total{outcome=completed} 1"
        k_note "$K_FDS" "a 64-port TCP stream, the ssh stream and a UDP stream handed over (a table past 32 fds), upgrade completed, 64 of 64 ports and the UDP stream answering"
    else
        k_fail "$K_FDS" "lorica_hot_upgrade_total{outcome=completed} on the new generation is '${COMPLETED}'"
    fi

    # ---- UDP across the upgrade ------------------------------------------
    wait "$UDP_BG"
    UDP_RESULT=$(tail -n 1 "$K_DIR/udp.json")
    UDP_SENT=$(printf '%s' "$UDP_RESULT" | jq -r '.sent // 0' 2>/dev/null)
    UDP_LOST=$(printf '%s' "$UDP_RESULT" | jq -r '.lost // "?"' 2>/dev/null)
    UDP_LATE=$(printf '%s' "$UDP_RESULT" | jq -r '.late // "?"' 2>/dev/null)
    if [ "${UDP_SENT:-0}" -ge 600 ] 2>/dev/null && [ "$UDP_LOST" = 0 ] && [ "$UDP_LATE" = 0 ]; then
        k_ok "$K_UDP" "${UDP_SENT} queries 50 ms apart across the upgrade, every one answered within 1 s"
    else
        k_fail "$K_UDP" "queries across the upgrade: ${UDP_RESULT}"
    fi
    DRAINING_DROPS=$(k_series lorica_stream_datagrams_dropped_total "stream_id=\"${UDP_SID}\"" 'reason="binding_draining"')
    if [ -z "$DRAINING_DROPS" ] || [ "$DRAINING_DROPS" = 0 ]; then
        k_ok "$K_UDP" "no binding_draining drop on the new generation (${DRAINING_DROPS:-no series})"
        k_note "$K_UDP" "${UDP_SENT} queries every 50 ms from T0-3 s to T0+32 s, 0 lost, 0 late, no binding_draining drop"
    else
        k_fail "$K_UDP" "lorica_stream_datagrams_dropped_total{reason=binding_draining} is ${DRAINING_DROPS}"
    fi

    # ---- IV1: session A through the drain --------------------------------
    k_sleep_until $(( T0 + 115 ))
    A_TICK=$(k_last_tick a)
    if kill -0 "$SSH_A" 2>/dev/null && [ "${A_TICK:-0}" -ge $(( T0 + 113 )) ]; then
        k_ok "$K_IV1" "session A still prints at T0+115 s (last tick T0+$(( A_TICK - T0 )) s)"
    else
        k_fail "$K_IV1" "session A at T0+115 s: last tick ${A_TICK:-none} (T0 ${T0}), exit $(cat "$K_DIR/a.code" 2>/dev/null || echo running)"
    fi
    while [ ! -f "$K_DIR/a.code" ] && [ "$(k_now)" -lt $(( T0 + 150 )) ]; do
        sleep 0.5
    done
    A_END=$(k_now)
    A_TICK=$(k_last_tick a)
    if [ -f "$K_DIR/a.code" ]; then
        k_ok "$K_IV1" "session A ended at T0+$(( A_END - T0 )) s, last tick T0+$(( ${A_TICK:-0} - T0 )) s, ssh exit $(cat "$K_DIR/a.code")"
    else
        k_fail "$K_IV1" "session A still open at T0+150 s"
        kill "$SSH_A" 2>/dev/null
    fi
    if grep -q "closed by remote host" "$K_DIR/a.err" 2>/dev/null; then
        k_ok "$K_IV1" "ssh reports the connection closed by remote host (a FIN)"
    else
        k_fail "$K_IV1" "ssh did not report a close by the remote host: $(tr '\r\n' '  ' < "$K_DIR/a.err" 2>/dev/null | head -c 300)"
    fi

    LOGGED=""
    for i in $(seq 1 40); do
        LOGGED=$(api_get "/api/v1/stream-logs?stream_id=${SSH_SID}&end_reason=drained_by_upgrade" \
            | jq -r '[.data.entries[] | select(.listen_port == '"$SSH_PORT"')] | length' 2>/dev/null)
        [ "${LOGGED:-0}" -ge 1 ] 2>/dev/null && break
        sleep 0.5
    done
    if [ "$LOGGED" = 1 ]; then
        k_ok "$K_IV1" "the stream log lists the connection with end_reason=drained_by_upgrade"
    else
        k_fail "$K_IV1" "stream log rows ended drained_by_upgrade on the ssh stream: '${LOGGED}' (1 expected)"
    fi

    DRAINED=""
    for i in $(seq 1 120); do
        DRAINED=$(k_series lorica_hot_upgrade_stream_connections_total "stream_id=\"${SSH_SID}\"" 'outcome="drained"')
        [ "$DRAINED" = 1 ] && break
        sleep 1
    done
    REPORT_AT=$(( $(k_now) - T0 ))
    DRAIN_COUNT=$(k_metrics | grep '^lorica_hot_upgrade_drain_seconds_count' | awk '{print $NF}' | head -1)
    COMPLETED=$(hu_counter completed)
    if [ "$DRAINED" = 1 ] && [ "${DRAIN_COUNT:-0}" -ge 1 ] 2>/dev/null && [ "$COMPLETED" = 1 ]; then
        k_ok "$K_IV1" "new /metrics at T0+${REPORT_AT} s: stream_connections_total{outcome=drained} 1, drain_seconds_count ${DRAIN_COUNT}, hot_upgrade_total{completed} 1"
        k_note "$K_IV1" "drain ${DRAIN_S} s; session alive at T0+115 s, closed by remote host at T0+$(( A_END - T0 )) s; one stream-log row drained_by_upgrade; report on the new /metrics (drained 1, drain_seconds_count ${DRAIN_COUNT}, completed 1)"
    else
        k_fail "$K_IV1" "new /metrics: drained='${DRAINED}' drain_seconds_count='${DRAIN_COUNT}' completed='${COMPLETED}'"
    fi

    # ---- Session B outlives the old generation ---------------------------
    k_sleep_until $(( T0 + 150 ))
    B_TICK=$(k_last_tick b)
    AFTER_PREVIOUS=$(k_preview | jq -r '.data.previous_generation')
    if kill -0 "$SSH_B" 2>/dev/null && [ ! -f "$K_DIR/b.code" ] && [ "${B_TICK:-0}" -ge $(( T0 + 148 )) ] \
        && [ "$AFTER_PREVIOUS" = null ]; then
        k_ok "$K_NEW" "session B, opened at T0+10 s, still prints at T0+150 s, after the old generation left"
        k_note "$K_NEW" "session B opened at T0+10 s alive at T0+150 s with the old generation gone"
    else
        k_fail "$K_NEW" "session B at T0+150 s: last tick ${B_TICK:-none} (T0 ${T0}), exit $(cat "$K_DIR/b.code" 2>/dev/null || echo running), previous_generation ${AFTER_PREVIOUS}: $(tr '\r\n' '  ' < "$K_DIR/b.err" 2>/dev/null | head -c 200)"
    fi
    kill "$SSH_B" 2>/dev/null
    pkill -f "tester@${STREAM_HOST}" 2>/dev/null
fi

# ---- Cleanup: streams, backends, the drain setting ---------------------
for sid in "${SSH_SID:-}" "${UDP_SID:-}" "${RANGE_SID:-}"; do
    case "$sid" in ""|refused*) ;; *) api_del "/api/v1/streams/$sid" >/dev/null ;; esac
done
for bid in "${SSH_BID:-}" "${UDP_BID:-}" "${RANGE_BID:-}"; do
    [ -n "$bid" ] && api_del "/api/v1/backends/$bid" >/dev/null
done
case "$DRAIN_BEFORE" in
    ''|null) ;;
    *) api_put /api/v1/settings "{\"worker_drain_timeout_s\":${DRAIN_BEFORE}}" >/dev/null ;;
esac

for name in $K_ALL; do
    k_line "$name"
done

# =========================================================================
# Story 12.1 AC #3, the hot rollback to 1.10.7 (Story 12.12 D-h and
# Resolved 7, Lot L). Last in this smoke: it leaves the node on 1.10.7.
# With exactly one TCP stream bound, the released 1.10.7 binary
# (published on the shared volume by `hot-upgrade-baseline`) is signed
# with the smoke's key and uploaded as an upgrade, the rollback
# docs/hot-upgrade.md describes, under sustained HTTP traffic.
#
# The outcomes Resolved 7 accepts pass, and the line says which: the
# handoff completes (a new pid serves the management API without the
# stream API, so 1.10.7; no request failed; the route still answers) and
# the stream's port is not taken over by anything but the stream, or
# 1.10.7 is refused (`exec_failed`) and the old generation keeps serving
# the route and the stream. A crash, a failed request, or the stream's
# listener lost to another use fails: the port answering HTTP after the
# handoff is that last case.
# Prints exactly one `L4-SCENARIO` line (Story 12.12 D-c).
# =========================================================================
log "=== 12.1 AC #3: hot rollback to 1.10.7 with a TCP stream bound ==="
HR_NAME=12.1-ac3-rollback-hot-1.10.7
HR_BIN=/shared/lorica-1.10.7
HR_PORT=7801
hr_line() {
    echo "L4-SCENARIO $HR_NAME $1 $2"
    if [ "$1" = PASS ]; then ok "$HR_NAME: $2"; else fail "$HR_NAME: $2"; fi
}
# GET <path> on the management API into $HR_BODY, printing the status
# and logging in again on a 401: the replacement binary may not honour
# the session the smoke holds. Callers run it in a command substitution,
# so the body and the session live in files, not in variables.
HR_BODY=/tmp/hr_body
HR_SESSION=/tmp/hr_session
printf '%s' "$SESSION" > "$HR_SESSION"
hr_api() {
    local code
    code=$(curl -sk -o "$HR_BODY" -w '%{http_code}' -b "$(cat "$HR_SESSION")" "$API$1" 2>/dev/null || echo 000)
    if [ "$code" = 401 ]; then
        local hdr
        hdr=$(mktemp)
        curl -sk -o /dev/null -D "$hdr" "$API/api/v1/auth/login" -X POST -H "Content-Type: application/json" \
            -d "$(jq -nc --arg pw "${NEW_PW:-$ADMIN_PW}" '{username: "admin", password: $pw}')" 2>/dev/null || true
        grep -io 'lorica_session=[^;]*' "$hdr" | head -1 | tr -d '\r\n' > "$HR_SESSION"
        rm -f "$hdr"
        code=$(curl -sk -o "$HR_BODY" -w '%{http_code}' -b "$(cat "$HR_SESSION")" "$API$1" 2>/dev/null || echo 000)
    fi
    echo "$code"
}
# `<pid> <status of GET /api/v1/streams>`: the stream API is 1.11.0's,
# 1.10.7 answers it 404. (The version in /api/v1/system is MAJOR.MINOR
# and both binaries read 1.10 until the bump.)
hr_generation() {
    local pid streams
    [ "$(hr_api /api/v1/system)" = 200 ] && pid=$(jq -r '.data.proxy.pid // "-"' "$HR_BODY")
    rm -f "$HR_BODY"
    streams=$(hr_api /api/v1/streams)
    rm -f "$HR_BODY"
    echo "${pid:--} ${streams}"
}
hr_exec_failed() {
    local v
    if [ "$(hr_api /metrics)" = 200 ]; then
        v=$(grep '^lorica_hot_upgrade_total{' "$HR_BODY" | grep 'outcome="exec_failed"' | awk '{print $NF}' | head -1)
    fi
    rm -f "$HR_BODY"
    echo "${v:-0}"
}
# One HTTP request on the stream port with Host <host>: the status
# line's code, `refused`, or what else happened. Through the stream it
# reaches backend1, which answers any host; an HTTP proxy on the port
# would route by host instead.
hr_on_stream_port() {
    python3 - "$PROXY" "$HR_PORT" "$1" <<'PY'
import socket, sys
host = sys.argv[1].split("//", 1)[1].split(":", 1)[0]
try:
    s = socket.create_connection((host, int(sys.argv[2])), timeout=3)
except ConnectionRefusedError:
    print("refused")
    sys.exit(0)
except OSError as e:
    print(f"unreachable ({e.__class__.__name__})")
    sys.exit(0)
s.settimeout(3)
s.sendall(f"GET /healthz HTTP/1.0\r\nHost: {sys.argv[3]}\r\n\r\n".encode())
try:
    head = s.recv(256).decode("latin-1").split("\r\n")[0]
except OSError as e:
    head = f"no answer ({e.__class__.__name__})"
print(head.split(" ")[1] if head.startswith("HTTP/") else head or "closed")
PY
}
hr() {
    local i ids backend_ip backend stream through preview sig code exec_before before after v consec=0 \
        outcome="" total failed after_route after_api after_unrouted after_routed exec_after
    for i in $(seq 1 60); do
        [ -s "$HR_BIN" ] && break
        sleep 1
    done
    [ -s "$HR_BIN" ] || { hr_line FAIL "the 1.10.7 binary was not published at ${HR_BIN}"; return; }

    # Exactly one stream on the node: an earlier section's streams would
    # change what the handoff table carries.
    [ "$(hr_api /api/v1/streams)" = 200 ] && ids=$(jq -r '(.data.streams // [])[].id' "$HR_BODY")
    rm -f "$HR_BODY"
    for i in $ids; do api_del "/api/v1/streams/$i" >/dev/null; done
    backend_ip=$(python3 -c 'import socket, sys; print(socket.gethostbyname(sys.argv[1]))' "${BACKEND1%%:*}")
    backend=$(api_post /api/v1/backends "{\"address\":\"${backend_ip}:${BACKEND1##*:}\",\"health_check_enabled\":false}" | jq -r '.data.id // empty')
    [ -n "$backend" ] || { hr_line FAIL "backend create refused"; return; }
    stream=$(api_post /api/v1/streams "{\"name\":\"hr-stream\",\"protocol\":\"tcp\",\"listen_address\":\"0.0.0.0\",\"port_first\":${HR_PORT},\"backend_ids\":[\"${backend}\"]}" | jq -r '.data.id // empty')
    [ -n "$stream" ] || { hr_line FAIL "stream create refused"; return; }
    for i in $(seq 1 30); do
        through=$(hr_on_stream_port backend1)
        [ "$through" = 200 ] && break
        sleep 1
    done
    [ "$through" = 200 ] || { hr_line FAIL "the stream did not reach backend1 under 1.11.0: ${through}"; return; }
    # A deleted UDP stream keeps its sockets while its sessions drain:
    # wait until the preview lists this stream alone.
    for i in $(seq 1 45); do
        preview=""
        [ "$(hr_api /api/v1/system/upgrade/preview)" = 200 ] \
            && preview=$(jq -r '[(.data.streams // [])[].stream_id] | join(",")' "$HR_BODY")
        rm -f "$HR_BODY"
        [ "$preview" = "$stream" ] && break
        sleep 1
    done
    [ "$preview" = "$stream" ] || { hr_line FAIL "the node binds other streams than ${stream}: ${preview}"; return; }

    sig=$(openssl pkeyutl -sign -inkey "$PRIV_GOOD" -rawin -in "$HR_BIN" 2>/dev/null | od -An -v -tx1 | tr -d ' \n')
    [ "${#sig}" = 128 ] || { hr_line FAIL "could not sign the 1.10.7 binary"; return; }
    exec_before=$(hr_exec_failed)
    before=$(hr_generation)
    [ "${before#* }" = 200 ] || { hr_line FAIL "the node does not serve the stream API before the rollback: ${before}"; return; }

    local traffic=/tmp/hr_traffic.log flag=/tmp/hr_run_traffic bg
    : > "$traffic"
    : > "$flag"
    (
        while [ -f "$flag" ]; do
            proxy_code >> "$traffic"
            echo >> "$traffic"
        done
    ) &
    bg=$!
    sleep 2
    code=$(curl -s -o /tmp/hr_resp.json -w '%{http_code}' -b "$SESSION" \
        -F "binary=@${HR_BIN};type=application/octet-stream" -F "signature=${sig}" \
        "$API/api/v1/system/upgrade" 2>/dev/null || echo 000)
    if [ "$code" != 200 ]; then
        rm -f "$flag"; wait "$bg" 2>/dev/null || true
        hr_line FAIL "the signed 1.10.7 upload answered ${code}: $(tr '\n' ' ' < /tmp/hr_resp.json | head -c 200)"
        return
    fi
    # Settle on one outcome: the old supervisor counting exec_failed, or
    # five reads in a row from one new pid that answers the stream API
    # 404 (both generations answer the API during the overlap, as IV3
    # above says).
    for i in $(seq 1 90); do
        exec_after=$(hr_exec_failed)
        if [ "$exec_after" -gt "$exec_before" ] 2>/dev/null; then
            outcome=refused
            break
        fi
        v=$(hr_generation)
        if [ "${v#* }" = 404 ] && [ "${v%% *}" != "${before%% *}" ] && [ "${v%% *}" != - ]; then
            if [ "$v" = "${after:-}" ]; then consec=$((consec + 1)); else after="$v"; consec=1; fi
            if [ "$consec" -ge 5 ]; then outcome=completed; break; fi
        else
            consec=0
        fi
        sleep 1
    done
    # Past the old generation's drain (worker_drain_timeout_s, 30 s), so
    # what serves now is what stays.
    [ "$outcome" = completed ] && sleep 35
    rm -f "$flag"
    wait "$bg" 2>/dev/null || true
    total=$(wc -l < "$traffic" | tr -d ' ')
    failed=$(grep -cvE '^2[0-9][0-9]$' "$traffic" || true)
    after_route=$(proxy_code)
    after_api=$(hr_generation)
    after_unrouted=$(hr_on_stream_port backend1)
    after_routed=$(hr_on_stream_port "$PROXY_HOST")

    case "$outcome" in
        completed)
            if [ "$failed" != 0 ] || [ "${after_route:0:1}" != 2 ] || [ "${after_api#* }" != 404 ]; then
                hr_line FAIL "handoff to 1.10.7 completed (pid and stream API ${before} -> ${after}) but ${failed} of ${total} requests failed, route now ${after_route}, API now ${after_api}"
            else
                case "$after_unrouted $after_routed" in
                    [0-9][0-9][0-9]\ [0-9][0-9][0-9])
                        hr_line FAIL "handoff to 1.10.7 completed (pid and stream API ${before} -> ${after}), ${total} requests across it, 0 failed; but 1.10.7 serves HTTP on the stream's port ${HR_PORT}: the stream listener was handed over and adopted as an HTTP proxy listener (Host ${PROXY_HOST}: ${after_routed}, Host backend1: ${after_unrouted}; through the stream backend1 answered 200 for any host)"
                        ;;
                    *)
                        hr_line PASS "handoff to 1.10.7 completed (pid and stream API ${before} -> ${after}), ${total} requests across it, 0 failed; route ${after_route}; the stream's port ${HR_PORT}: ${after_unrouted}"
                        ;;
                esac
            fi
            ;;
        refused)
            if [ "$failed" != 0 ] || [ "${after_route:0:1}" != 2 ] || [ "$after_api" != "$before" ] || [ "$after_unrouted" != 200 ]; then
                hr_line FAIL "1.10.7 refused (exec_failed ${exec_before} -> ${exec_after}) but ${failed} of ${total} requests failed, route ${after_route}, pid and stream API ${after_api} (were ${before}), stream ${after_unrouted}"
            else
                hr_line PASS "1.10.7 refused the handoff (exec_failed ${exec_before} -> ${exec_after}): the old generation (${before}) kept serving, ${total} requests 0 failed, route ${after_route}, backend1 through the stream ${after_unrouted}"
            fi
            ;;
        *)
            hr_line FAIL "no outcome within 90 s: pid and stream API ${after_api} (were ${before}), exec_failed ${exec_before} -> ${exec_after}, ${failed} of ${total} requests failed, route ${after_route}, stream port ${after_unrouted}"
            ;;
    esac
}
# Without errexit: every path of hr ends on its one line.
set +e
hr
set -e

print_results
