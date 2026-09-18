#!/usr/bin/env bash
# =============================================================================
# Lorica traffic-capture E2E smoke (v1.8.0 Stories 10.1 and 10.2)
#
# Pre-requisite: the `capture` compose profile is up: one node built with
# `--features otel` on two networks (the e2e one and `capture-inside`,
# pinned to 172.30.0.0/16), the socat syslog collector appending frames
# to /shared/syslog.log, the logs-only OTel collector writing
# /shared/otlp-logs.json, the node's stdout copied to /shared/lorica.log,
# a writable /shared/captures and a read-only /captures-ro.
#
# What it asserts, and which story each belongs to:
#   10.1 IV1  a rule on route R with source_cidrs [172.30.0.0/16] and
#             status [server_error]: /fail from inside is one record each
#             with the full request body, /ok from inside is none, /fail
#             from outside is none; on the ring and in the syslog frames
#   10.1 IV2  a 10 MiB body against the 64 KiB default cap: truncated,
#             body_bytes_total 10 MiB, 65 536 kept bytes, the upstream
#             counted all 10 MiB; a sibling route without a rule leaves
#             the ring untouched
#   10.1 IV3  max_captures 3 disables the rule after the third emission
#             with an audit row whose payload hash says max_captures;
#             ttl_seconds 120 clears `enabled` within 130 s with a row
#             whose payload says expired
#   10.2 IV1  Authorization and Cookie read <redacted:N bytes> on stdout,
#             in the syslog collector and in the OTLP collector, and the
#             collector-side record joins the access-log row on request_id
#   10.2 IV2  output.dir on a read-only mount: requests flow with zero
#             5xx, the record is dropped, dropped_sink increments; then a
#             writable dir: one 0640 file per capture named
#             <timestamp>-<request_id>.json, byte-identical to the download
#   10.2 IV3  an application/octet-stream body round-trips through base64
#   10.2 IV4  a rule naming X-Api-Key redacts it and Authorization stays
#             redacted
#   audit C1  a WAF block on a route with a 4xx rule is captured with the
#             WAF's 403 and a null request body_skipped
#   roles     an Operator can disable and cannot create; a Viewer cannot
#             read the ring
#
# CAPTURE_SMOKE_WORKERS=1 runs the same assertions against a node started
# with `--workers 2` (the `capture-workers` compose profile). Three things
# differ there and nothing else does (docs/capture.md):
#   - the recent-captures ring is per worker and this API runs in the
#     supervisor, whose ring is empty, so both `/capture/recent`
#     endpoints answer 503. The records are read from the always-on
#     `lorica::capture` stdout sink instead, which holds the same
#     documents byte for byte;
#   - `max_captures` is spent per worker, so a rule stops somewhere
#     between its budget and CAPTURE_WORKERS times its budget, and each
#     worker that spends its own copy queues its own auto-disable;
#   - a configuration change reaches the workers over the supervisor RPC
#     rather than in-process, so the settle after a write is longer.
# What only a workers node can show lives in run-capture-workers-smoke.sh.
#
# The syslog file is RFC 6587 octet-counted frames with no separator, so
# a small Python parser walks it; the OTLP file and the node log are one
# JSON document per line and are grepped. Every audit row keeps SHA-256
# of the compact payload rather than the text (the automation smoke has
# the same shape), so the expected payload is hashed and compared.
# =============================================================================

set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
source "$SCRIPT_DIR/helpers.sh"

API="${LORICA_API}"
INSIDE_HOST="${INSIDE_HOST:-lorica-capture-inside}"
OUTSIDE_HOST="${OUTSIDE_HOST:-lorica-capture-outside}"
BACKEND1="${BACKEND1_ADDR}"
SYSLOG_LOG="${SYSLOG_LOG:-/shared/syslog.log}"
OTLP_LOG="${OTLP_LOG:-/shared/otlp-logs.json}"
LORICA_LOG="${LORICA_LOG:-/shared/lorica.log}"
CAPTURE_DIR="${CAPTURE_DIR:-/shared/captures}"
CAPTURE_RO_DIR="${CAPTURE_RO_DIR:-/captures-ro}"
INSIDE_CIDR="${INSIDE_CIDR:-172.30.0.0/16}"
SYSLOG_ENDPOINT="${SYSLOG_ENDPOINT:-syslog-collector-capture:6601}"
OTLP_ENDPOINT="${OTLP_ENDPOINT:-http://otelcol-logs-capture:4318}"

# Worker mode: see the header. CAPTURE_WORKERS is the node's worker
# count, the multiplier every per-process budget is spent against.
WORKERS_MODE=false
if [ "${CAPTURE_SMOKE_WORKERS:-0}" = "1" ]; then
    WORKERS_MODE=true
fi
CAPTURE_WORKERS="${CAPTURE_WORKERS:-1}"

HOST_R="capture-r.local"
HOST_S="capture-s.local"
HOST_W="capture-waf.local"
KIB64=65536
MIB10=10485760

# ---------------------------------------------------------------------
# Helpers shared with run-capture-workers-smoke.sh: the syslog-frame and
# stdout-record readers, the proxy driver, login and the rule helpers.
# Sourced after the paths they read are set.
# ---------------------------------------------------------------------
source "$SCRIPT_DIR/capture-helpers.sh"

# Wait for a configuration write to reach the process that enforces it.
# In single-process mode that is this very process; under `--workers` the
# snapshot travels to each worker over the supervisor RPC first.
settle() {
    if [ "$WORKERS_MODE" = true ]; then
        sleep 5
    else
        sleep 2
    fi
}
disable_rule() { api_post "/api/v1/capture/rules/$1/disable" '{}' >/dev/null; settle; }

# Every record this node emitted, in the ring's listing shape.
#
# On a single-process node that is the ring itself. On a `--workers` node
# the ring lives in the workers and this API runs in the supervisor,
# which answers 503, so the records come from the stdout sink instead.
# The two sources carry the same documents; the stdout one is not capped
# at CAPTURE_RING_CAPACITY and never elides a body, which only ever makes
# the assertions below stricter.
ring() {
    if [ "$WORKERS_MODE" = true ]; then
        stdout_records
    else
        api_get /api/v1/capture/recent
    fi
}
ring_count_for_rule() { ring | jq -r --arg r "$1" '[(.data.captures // [])[] | select(.rule_id == $r)] | length'; }
ring_count_for_request() { ring | jq -r --arg id "$1" '[(.data.captures // [])[] | select(.request_id == $id)] | length'; }
ring_size() { ring | jq -r '(.data.captures // []) | length'; }
# Poll until the rule has at least $2 records on the ring (15 s).
wait_ring() {
    local rule="$1" want="$2" have=0
    for _ in $(seq 1 30); do
        have=$(ring_count_for_rule "$rule")
        [ "${have:-0}" -ge "$want" ] && return 0
        sleep 0.5
    done
    return 1
}
# The full record one rule produced for one request, to a file.
download_record() {
    # $1 request id, $2 rule id, $3 out file. Leaves DL_HEADERS behind.
    # On a workers node the download endpoint answers 503 like the
    # listing, so the record is taken from the stdout sink: the same
    # bytes, which is what the byte-identity assertions compare. The
    # headers file is created empty there, and the assertion that reads
    # it is skipped at its call site.
    DL_HEADERS=$(mktemp)
    if [ "$WORKERS_MODE" = true ]; then
        stdout_record_text "$1" "$2" > "$3"
        return
    fi
    curl -sk -b "$SESSION" -D "$DL_HEADERS" -o "$3" \
        "$API/api/v1/capture/recent/$1?rule_id=$2" 2>/dev/null || true
}

audit_rows() {
    # $1 action, $2 target_id
    api_get "/api/v1/audit?action=$1&limit=200" \
        | jq -c --arg t "$2" '[(.data.entries // [])[] | select(.target_id == $t)]'
}
sha256_of() { printf '%s' "$1" | sha256sum | awk '{print $1}'; }

metric_dropped_sink() {
    curl -sk -b "$SESSION" "$API/metrics" 2>/dev/null \
        | grep '^lorica_captures_total' \
        | grep "rule_id=\"$1\"" \
        | grep 'outcome="dropped_sink"' \
        | awk '{sum += $NF} END {printf "%d", sum}'
}

# ---------------------------------------------------------------------
# Preflight.
# ---------------------------------------------------------------------
log "=== capture smoke: preflight ==="
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

# Two proxy addresses, one per network alias (compose gives the node an
# alias on each of its networks because the embedded DNS answers the
# service name with one address only). The runner is on both networks,
# so the kernel picks the matching source address for each.
IN_IP=$(resolve_v4 "$INSIDE_HOST")
OUT_IP=$(resolve_v4 "$OUTSIDE_HOST")
PROXY_IN="http://${IN_IP}:8080"
PROXY_OUT="http://${OUT_IP}:8080"
if [ -n "$IN_IP" ] && in_cidr "$IN_IP" "$INSIDE_CIDR"; then
    ok "the node is reachable inside $INSIDE_CIDR at $PROXY_IN"
else
    fail "no node address inside $INSIDE_CIDR ($INSIDE_HOST resolved to '$IN_IP')"
    print_results
fi
if [ -n "$OUT_IP" ] && ! in_cidr "$OUT_IP" "$INSIDE_CIDR"; then
    ok "the node is also reachable outside $INSIDE_CIDR at $PROXY_OUT"
else
    fail "no node address outside $INSIDE_CIDR ($OUTSIDE_HOST resolved to '$OUT_IP')"
    print_results
fi

# --- Login (with first-run password change handling) ---
ADMIN_PW=""
for i in $(seq 1 60); do
    if [ -f /shared/admin_password ]; then
        ADMIN_PW=$(tr -d '[:space:]' < /shared/admin_password)
        break
    fi
    sleep 1
done
[ -n "$ADMIN_PW" ] || { fail "no admin password"; print_results; }

LOGIN_HEADERS=$(mktemp)
LOGIN_BODY=$(mktemp)
LOGIN_HTTP=$(curl -s -o "$LOGIN_BODY" -D "$LOGIN_HEADERS" \
    -w '%{http_code}' "$API/api/v1/auth/login" -X POST \
    -H "Content-Type: application/json" \
    -d "{\"username\":\"admin\",\"password\":\"${ADMIN_PW}\"}")
if [ "$LOGIN_HTTP" != "200" ]; then
    fail "login HTTP $LOGIN_HTTP: $(cat "$LOGIN_BODY")"
    print_results
fi
SESSION=$(grep -i 'Set-Cookie:' "$LOGIN_HEADERS" | grep -o 'lorica_session=[^;]*' | head -1)
[ -n "$SESSION" ] || { fail "no session cookie returned"; print_results; }
ok "initial login succeeded"

MUST_CHANGE=$(jq -r '.data.must_change_password // false' "$LOGIN_BODY")
if [ "$MUST_CHANGE" = "true" ]; then
    NEW_PW="CaptureSmokePassword!42"
    CHANGE_JSON=$(jq -nc --arg cur "$ADMIN_PW" --arg new "$NEW_PW" \
        '{"current_password":$cur,"new_password":$new}')
    CHANGE_HTTP=$(curl -s -o /dev/null -w '%{http_code}' -b "$SESSION" \
        "$API/api/v1/auth/password" -X PUT \
        -H "Content-Type: application/json" -d "$CHANGE_JSON")
    [ "$CHANGE_HTTP" = "200" ] || { fail "password change HTTP $CHANGE_HTTP"; print_results; }
    ok "first-run password rotated"
    SESSION=$(login_as admin "$NEW_PW")
    [ -n "$SESSION" ] || { fail "no session cookie after re-login"; print_results; }
fi
rm -f "$LOGIN_HEADERS" "$LOGIN_BODY"
ok "session ready"

# --- Sinks: the capture kind is on by default on both lanes ---
log "=== capture smoke: sinks ==="
SETTINGS=$(api_get /api/v1/settings)
assert_json "$SETTINGS" '.data.syslog_capture_enabled' 'true' 'syslog_capture_enabled defaults to true'
assert_json "$SETTINGS" '.data.otlp_logs_capture_enabled' 'true' 'otlp_logs_capture_enabled defaults to true'
SINKS_UPDATE=$(api_put /api/v1/settings "{
    \"syslog_endpoint\": \"${SYSLOG_ENDPOINT}\",
    \"syslog_transport\": \"tcp\",
    \"otlp_endpoint\": \"${OTLP_ENDPOINT}\",
    \"otlp_protocol\": \"http-proto\",
    \"otlp_logs_enabled\": true
}")
assert_json "$SINKS_UPDATE" '.data.syslog_endpoint' "$SYSLOG_ENDPOINT" 'syslog sink configured'
assert_json "$SINKS_UPDATE" '.data.otlp_logs_enabled' 'true' 'OTLP logs sink configured'
settle

# --- Backend and the three routes ---
log "=== capture smoke: backend and routes ==="
BACKEND=$(api_post /api/v1/backends "{
    \"name\": \"capture-backend1\",
    \"group\": \"capture\",
    \"address\": \"${BACKEND1}\",
    \"h2_upstream\": false,
    \"tls\": false
}")
BACKEND_ID=$(echo "$BACKEND" | jq -r '.data.id // empty')
[ -n "$BACKEND_ID" ] || { fail "backend create: $BACKEND"; print_results; }
ok "backend created (id=$BACKEND_ID)"

mk_route() {
    # $1 hostname, $2 extra JSON fields ("" for none)
    local extra="${2:-}"
    [ -n "$extra" ] && extra=", $extra"
    api_post /api/v1/routes "{\"hostname\":\"$1\",\"path_prefix\":\"/\",\"backend_ids\":[\"${BACKEND_ID}\"],\"enabled\":true${extra}}" \
        | jq -r '.data.id // empty'
}
ROUTE_R=$(mk_route "$HOST_R")
ROUTE_S=$(mk_route "$HOST_S")
ROUTE_W=$(mk_route "$HOST_W" '"waf_enabled":true,"waf_mode":"blocking"')
if [ -n "$ROUTE_R" ] && [ -n "$ROUTE_S" ] && [ -n "$ROUTE_W" ]; then
    ok "routes R ($ROUTE_R), S ($ROUTE_S) and W ($ROUTE_W, WAF blocking) created"
else
    fail "route creation: R='$ROUTE_R' S='$ROUTE_S' W='$ROUTE_W'"
    print_results
fi
settle
px "$PROXY_IN" "$HOST_R" /ok
[ "$PX_CODE" = "200" ] && ok "route R answers 200 on /ok" || fail "route R /ok answered $PX_CODE"
px "$PROXY_IN" "$HOST_R" /fail
[ "$PX_CODE" = "502" ] && ok "route R answers 502 on /fail" || fail "route R /fail answered $PX_CODE"

# ---------------------------------------------------------------------
# Story 10.1 IV3, the clock: armed first so its 120 s run under the
# rest of the smoke. Asserted at the end.
# ---------------------------------------------------------------------
log "=== 10.1 IV3: arming the ttl_seconds 120 rule ==="
mk_rule "{\"name\":\"ttl 120\",\"route_id\":\"$ROUTE_R\",\"match\":{\"path_prefix\":\"/never\"},\"emit\":{\"status\":[\"server_error\"]},\"limits\":{\"max_captures\":100,\"rate_per_minute\":100,\"ttl_seconds\":120}}"; RULE_TTL="$RULE_ID"
TTL_T0=$(date +%s)
if [ -n "$RULE_TTL" ]; then
    ok "ttl rule armed (id=$RULE_TTL)"
else
    fail "ttl rule refused: $RULE_OUT"
fi
TTL_EXPIRES_AT=$(rule_get "$RULE_TTL" | jq -r '.data.expires_at // empty')
assert_json "$(rule_get "$RULE_TTL")" '.data.enabled' 'true' 'ttl rule reads enabled'

# ---------------------------------------------------------------------
# Story 10.1 IV1: the source filter and the response predicate.
# ---------------------------------------------------------------------
log "=== 10.1 IV1: source_cidrs and status on route R ==="
mk_rule "{\"name\":\"inside 5xx\",\"route_id\":\"$ROUTE_R\",\"match\":{\"source_cidrs\":[\"$INSIDE_CIDR\"]},\"emit\":{\"status\":[\"server_error\"]}}"; RULE1="$RULE_ID"
if [ -n "$RULE1" ]; then
    ok "rule created with source_cidrs [$INSIDE_CIDR] and status [server_error] (id=$RULE1)"
else
    fail "rule create: $RULE_OUT"
    print_results
fi
assert_json "$RULE_OUT" '.data.capture.request_body_max_bytes' "$KIB64" 'capture defaults: 64 KiB request cap'
assert_json "$RULE_OUT" '.data.limits.max_captures' '100' 'capture defaults: max_captures 100'
assert_json "$RULE_OUT" '.data.limits.rate_per_minute' '10' 'capture defaults: rate_per_minute 10'
assert_json "$RULE_OUT" '.data.limits.ttl_seconds' '3600' 'capture defaults: ttl_seconds 3600'
settle

declare -a IN_FAIL_IDS=() IN_FAIL_BODIES=() IN_OK_IDS=() OUT_FAIL_IDS=()
for n in 1 2 3; do
    BODY="{\"n\":$n,\"probe\":\"inside-fail-$n\"}"
    px "$PROXY_IN" "$HOST_R" /fail -X POST -H 'Content-Type: application/json' -d "$BODY"
    [ "$PX_CODE" = "502" ] || fail "inside POST /fail #$n answered $PX_CODE"
    IN_FAIL_IDS+=("$(px_request_id)")
    IN_FAIL_BODIES+=("$BODY")
done
for n in 1 2; do
    px "$PROXY_IN" "$HOST_R" /ok -X POST -H 'Content-Type: application/json' -d "{\"probe\":\"inside-ok-$n\"}"
    [ "$PX_CODE" = "200" ] || fail "inside POST /ok #$n answered $PX_CODE"
    IN_OK_IDS+=("$(px_request_id)")
done
for n in 1 2; do
    px "$PROXY_OUT" "$HOST_R" /fail -X POST -H 'Content-Type: application/json' -d "{\"probe\":\"outside-fail-$n\"}"
    [ "$PX_CODE" = "502" ] || fail "outside POST /fail #$n answered $PX_CODE"
    OUT_FAIL_IDS+=("$(px_request_id)")
done
if [ -n "${IN_FAIL_IDS[0]}" ] && [ -n "${IN_OK_IDS[0]}" ] && [ -n "${OUT_FAIL_IDS[0]}" ]; then
    ok "the backend echoed the X-Request-Id of every request"
else
    fail "request ids missing from the backend's echo: in-fail='${IN_FAIL_IDS[*]}' in-ok='${IN_OK_IDS[*]}' out-fail='${OUT_FAIL_IDS[*]}'"
fi

if wait_ring "$RULE1" 3; then
    ok "three records reached the ring for the rule"
else
    fail "expected 3 ring records for the rule, got $(ring_count_for_rule "$RULE1")"
fi
RING=$(ring)
for i in 0 1 2; do
    RID="${IN_FAIL_IDS[$i]}"
    N=$(echo "$RING" | jq -r --arg id "$RID" --arg r "$RULE1" '[(.data.captures // [])[] | select(.request_id == $id and .rule_id == $r)] | length')
    if [ "$N" = "1" ]; then
        ok "inside /fail #$((i+1)) produced exactly one record ($RID)"
    else
        fail "inside /fail #$((i+1)) produced $N record(s), expected 1"
    fi
    REC=$(echo "$RING" | jq -c --arg id "$RID" --arg r "$RULE1" '[(.data.captures // [])[] | select(.request_id == $id and .rule_id == $r)] | .[0]')
    assert_json "$REC" '.request.body' "${IN_FAIL_BODIES[$i]}" "record #$((i+1)) carries the full request body"
    assert_json "$REC" '.request.body_encoding' 'utf8' "record #$((i+1)) body is utf8 (application/json)"
    assert_json "$REC" '.request.truncated' 'false' "record #$((i+1)) is not truncated"
    assert_json "$REC" '.response.status' '502' "record #$((i+1)) carries the 502"
    assert_json "$REC" '.route_id' "$ROUTE_R" "record #$((i+1)) names route R"
    CLIENT_IP=$(echo "$REC" | jq -r '.client_ip')
    if in_cidr "$CLIENT_IP" "$INSIDE_CIDR"; then
        ok "record #$((i+1)) client_ip $CLIENT_IP is inside $INSIDE_CIDR"
    else
        fail "record #$((i+1)) client_ip '$CLIENT_IP' is not inside $INSIDE_CIDR"
    fi
done
for RID in "${IN_OK_IDS[@]}"; do
    [ "$(ring_count_for_request "$RID")" = "0" ] && ok "inside /ok ($RID) produced no record" \
        || fail "inside /ok ($RID) produced a record"
done
for RID in "${OUT_FAIL_IDS[@]}"; do
    [ "$(ring_count_for_request "$RID")" = "0" ] && ok "outside /fail ($RID) produced no record" \
        || fail "outside /fail ($RID) produced a record"
done

# The syslog side of the same assertions: one capture frame per inside
# /fail, none for the others. Access frames exist for all seven.
SYSLOG_OK=false
for _ in $(seq 1 30); do
    [ "$(syslog_count capture "${IN_FAIL_IDS[2]}")" = "1" ] && { SYSLOG_OK=true; break; }
    sleep 1
done
[ "$SYSLOG_OK" = "true" ] || fail "the third capture frame never landed in syslog"
for i in 0 1 2; do
    RID="${IN_FAIL_IDS[$i]}"
    C=$(syslog_count capture "\"request_id\":\"$RID\"")
    [ "$C" = "1" ] && ok "syslog holds exactly one capture frame for inside /fail #$((i+1))" \
        || fail "syslog holds $C capture frame(s) for inside /fail #$((i+1)), expected 1"
    A=$(syslog_count access "\"request_id\":\"$RID\"")
    [ "$A" = "1" ] && ok "syslog holds the access frame with the same request_id (join key)" \
        || fail "syslog holds $A access frame(s) for $RID, expected 1"
done
for RID in "${IN_OK_IDS[@]}" "${OUT_FAIL_IDS[@]}"; do
    C=$(syslog_count capture "\"request_id\":\"$RID\"")
    [ "$C" = "0" ] && ok "syslog holds no capture frame for $RID" \
        || fail "syslog holds $C capture frame(s) for $RID, expected 0"
done
FRAME=$(syslog_body capture "\"request_id\":\"${IN_FAIL_IDS[0]}\"")
assert_json "$FRAME" '.kind' 'capture' 'the syslog capture body is stamped kind=capture'
assert_json "$FRAME" '.v' '1' 'the syslog capture body carries the body version'
assert_json "$FRAME" '.request.body' "${IN_FAIL_BODIES[0]}" 'the syslog capture body carries the request body'

for _ in $(seq 1 15); do
    [ "$(rule_get "$RULE1" | jq -r '.data.captures_emitted')" = "3" ] && break
    sleep 1
done
assert_json "$(rule_get "$RULE1")" '.data.captures_emitted' '3' 'captures_emitted flushed to the stored rule'
disable_rule "$RULE1"

# ---------------------------------------------------------------------
# Story 10.1 IV2: the cap, the upstream, the sibling route.
# ---------------------------------------------------------------------
log "=== 10.1 IV2: a 10 MiB body against the 64 KiB cap ==="
mk_rule "{\"name\":\"cap 64k\",\"route_id\":\"$ROUTE_R\",\"emit\":{\"status\":[\"server_error\"]},\"limits\":{\"max_captures\":100,\"rate_per_minute\":100,\"ttl_seconds\":3600}}"; RULE2="$RULE_ID"
[ -n "$RULE2" ] && ok "rule with default caps created (id=$RULE2)" || fail "rule create: $RULE_OUT"
settle
BIG=$(mktemp)
head -c "$MIB10" /dev/zero | tr '\0' 'a' > "$BIG"
px "$PROXY_IN" "$HOST_R" /fail -X POST -H 'Content-Type: text/plain' --data-binary "@$BIG"
[ "$PX_CODE" = "502" ] && ok "10 MiB POST /fail answered 502" || fail "10 MiB POST /fail answered $PX_CODE"
assert_json "$PX_BODY" '.body_length' "$MIB10" 'the upstream received all 10 MiB'
BIG_RID=$(px_request_id)
if wait_ring "$RULE2" 1; then
    ok "the 10 MiB exchange produced a record"
else
    fail "no record for the 10 MiB exchange"
fi
BIG_REC=$(mktemp)
download_record "$BIG_RID" "$RULE2" "$BIG_REC"
assert_json "$(cat "$BIG_REC")" '.request.truncated' 'true' 'record is truncated'
assert_json "$(cat "$BIG_REC")" '.request.body_bytes_total' "$MIB10" 'body_bytes_total is 10 MiB'
assert_json "$(cat "$BIG_REC")" '.request.body | length' "$KIB64" 'the kept body is 65 536 bytes'
assert_json "$(cat "$BIG_REC")" '.request.body_skipped' 'null' 'body_skipped is null'
rm -f "$BIG" "$BIG_REC"

# The sibling route: same backend, no rule.
SIZE_BEFORE=$(ring_size)
declare -a SIB_IDS=()
for n in 1 2 3; do
    px "$PROXY_IN" "$HOST_S" /fail -X POST -H 'Content-Type: application/json' -d "{\"sibling\":$n}"
    [ "$PX_CODE" = "502" ] || fail "sibling POST /fail #$n answered $PX_CODE"
    SIB_IDS+=("$(px_request_id)")
done
settle
SIZE_AFTER=$(ring_size)
[ "$SIZE_AFTER" = "$SIZE_BEFORE" ] && ok "the ring did not grow for the sibling route ($SIZE_BEFORE records)" \
    || fail "the ring grew from $SIZE_BEFORE to $SIZE_AFTER on the sibling route"
for RID in "${SIB_IDS[@]}"; do
    [ "$(ring_count_for_request "$RID")" = "0" ] && ok "sibling request $RID produced no record" \
        || fail "sibling request $RID produced a record"
done
disable_rule "$RULE2"

# ---------------------------------------------------------------------
# Story 10.1 IV3, the total.
# ---------------------------------------------------------------------
log "=== 10.1 IV3: max_captures 3 ==="
mk_rule "{\"name\":\"three then stop\",\"route_id\":\"$ROUTE_R\",\"emit\":{\"status\":[\"server_error\"]},\"limits\":{\"max_captures\":3,\"rate_per_minute\":100,\"ttl_seconds\":3600}}"; RULE3="$RULE_ID"
[ -n "$RULE3" ] && ok "rule with max_captures 3 created (id=$RULE3)" || fail "rule create: $RULE_OUT"
settle
for n in 1 2 3 4 5; do
    px "$PROXY_IN" "$HOST_R" /fail -X POST -H 'Content-Type: application/json' -d "{\"budget\":$n}"
    [ "$PX_CODE" = "502" ] || fail "budget POST /fail #$n answered $PX_CODE"
done
DISABLED=false
for _ in $(seq 1 20); do
    [ "$(rule_get "$RULE3" | jq -r '.data.enabled')" = "false" ] && { DISABLED=true; break; }
    sleep 1
done
[ "$DISABLED" = "true" ] && ok "the rule disabled itself after spending max_captures" \
    || fail "the rule is still enabled 20 s after five 5xx exchanges"
# The budget is per process, so under `--workers` each worker spends its
# own copy of max_captures and the node emits more than three: at least
# the budget (some worker spent all of it, which is what disabled the
# rule), at most the budget times the worker count, and never more than
# the five exchanges that were sent. In single-process mode both bounds
# collapse to exactly three. This is the documented semantics
# (docs/capture.md, "Budgets"), not a miscount.
EMIT_LOW=3
EMIT_HIGH=$(( 3 * CAPTURE_WORKERS ))
[ "$EMIT_HIGH" -gt 5 ] && EMIT_HIGH=5
EMITTED=$(ring_count_for_rule "$RULE3")
if [ "${EMITTED:-0}" -ge "$EMIT_LOW" ] && [ "${EMITTED:-0}" -le "$EMIT_HIGH" ]; then
    ok "$EMITTED record(s) emitted, within the per-process budget [$EMIT_LOW, $EMIT_HIGH]"
else
    fail "$EMITTED records for the rule, expected between $EMIT_LOW and $EMIT_HIGH"
fi
STORED=$(rule_get "$RULE3" | jq -r '.data.captures_emitted')
if [ "${STORED:-0}" -ge "$EMIT_LOW" ] && [ "${STORED:-0}" -le "$EMIT_HIGH" ]; then
    ok "captures_emitted is $STORED, the sum of what each process flushed"
else
    fail "captures_emitted is '$STORED', expected between $EMIT_LOW and $EMIT_HIGH"
fi
ROWS=""
for _ in $(seq 1 10); do
    ROWS=$(audit_rows capture.rule.auto_disabled "$RULE3")
    [ "$(echo "$ROWS" | jq 'length')" -ge 1 ] && break
    sleep 1
done
# One row per process that spent its own copy of the budget: exactly one
# in single-process mode, up to one per worker otherwise.
ROW_COUNT=$(echo "$ROWS" | jq 'length')
if [ "${ROW_COUNT:-0}" -ge 1 ] && [ "${ROW_COUNT:-0}" -le "$CAPTURE_WORKERS" ]; then
    ok "$ROW_COUNT capture.rule.auto_disabled audit row(s) name the rule"
else
    fail "$ROW_COUNT auto_disabled row(s) for the rule, expected between 1 and $CAPTURE_WORKERS"
fi
EXPECTED=$(jq -nc --arg r "$ROUTE_R" --arg id "$RULE3" '{budget:"max_captures",enabled:false,limit:3,route_id:$r,rule_id:$id}')
ROW_HASH=$(echo "$ROWS" | jq -r '.[0].after_payload_hash // ""')
if [ "$ROW_HASH" = "$(sha256_of "$EXPECTED")" ]; then
    ok "the audit payload says budget=max_captures, limit=3"
else
    fail "the audit payload hash '$ROW_HASH' is not that of $EXPECTED"
fi
assert_json "$ROWS" '.[0].operator_username' 'capture' 'the actor is the node (capture)'

# ---------------------------------------------------------------------
# Story 10.2 IV1: redaction on every output, and the join.
# ---------------------------------------------------------------------
log "=== 10.2 IV1: Authorization and Cookie are redacted on stdout, syslog and OTLP ==="
mk_rule "{\"name\":\"redaction\",\"route_id\":\"$ROUTE_R\",\"emit\":{\"status\":[\"server_error\"]},\"limits\":{\"max_captures\":100,\"rate_per_minute\":100,\"ttl_seconds\":3600}}"; RULE5="$RULE_ID"
[ -n "$RULE5" ] && ok "redaction rule created (id=$RULE5)" || fail "rule create: $RULE_OUT"
settle
# A GET, on purpose: the fixture backend echoes the request headers in
# its POST responses, and a response body is never redacted, so a POST
# would put the raw bearer value in the record legitimately. The
# request id comes from the ring (this rule has exactly one record).
px "$PROXY_IN" "$HOST_R" /fail -H 'Authorization: Bearer x' -H 'Cookie: s=y'
[ "$PX_CODE" = "502" ] && ok "the credentialed GET /fail answered 502" || fail "credentialed GET /fail answered $PX_CODE"
wait_ring "$RULE5" 1 || fail "no record for the credentialed exchange"
RED_RID=$(ring | jq -r --arg r "$RULE5" '[(.data.captures // [])[] | select(.rule_id == $r)] | .[0].request_id // empty')
[ -n "$RED_RID" ] && ok "the credentialed exchange is on the ring (request_id $RED_RID)" || fail "no ring record for the redaction rule"
RED_REC=$(mktemp)
download_record "$RED_RID" "$RULE5" "$RED_REC"
hdr() { jq -r --arg n "$2" '[.request.headers[] | select((.[0] | ascii_downcase) == $n) | .[1]] | join(",")' "$1"; }
[ "$(hdr "$RED_REC" authorization)" = "<redacted:8 bytes>" ] && ok "ring: Authorization reads <redacted:8 bytes>" \
    || fail "ring: Authorization reads '$(hdr "$RED_REC" authorization)'"
[ "$(hdr "$RED_REC" cookie)" = "<redacted:3 bytes>" ] && ok "ring: Cookie reads <redacted:3 bytes>" \
    || fail "ring: Cookie reads '$(hdr "$RED_REC" cookie)'"
grep -q 'Bearer x' "$RED_REC" && fail "ring: the bearer value leaked into the record" || ok "ring: the bearer value is absent from the record"
rm -f "$RED_REC"

# stdout: the node log copied to /shared/lorica.log, target lorica::capture.
STDOUT_LINE=""
for _ in $(seq 1 15); do
    STDOUT_LINE=$(grep 'lorica::capture' "$LORICA_LOG" 2>/dev/null | grep "$RED_RID" | head -1 || true)
    [ -n "$STDOUT_LINE" ] && break
    sleep 1
done
if [ -n "$STDOUT_LINE" ]; then
    ok "stdout: a lorica::capture line carries the request id"
    echo "$STDOUT_LINE" | grep -q '<redacted:8 bytes>' && ok "stdout: Authorization is <redacted:8 bytes>" || fail "stdout: no <redacted:8 bytes>"
    echo "$STDOUT_LINE" | grep -q '<redacted:3 bytes>' && ok "stdout: Cookie is <redacted:3 bytes>" || fail "stdout: no <redacted:3 bytes>"
    echo "$STDOUT_LINE" | grep -q 'Bearer x' && fail "stdout: the bearer value leaked" || ok "stdout: the bearer value is absent"
    echo "$STDOUT_LINE" | grep -q 's=y' && fail "stdout: the cookie value leaked" || ok "stdout: the cookie value is absent"
else
    fail "stdout: no lorica::capture line for $RED_RID in $LORICA_LOG"
fi

# syslog: the capture frame and the access frame with the same id.
for _ in $(seq 1 30); do
    [ "$(syslog_count capture "\"request_id\":\"$RED_RID\"")" = "1" ] && break
    sleep 1
done
SYS_BODY=$(syslog_body capture "\"request_id\":\"$RED_RID\"")
if [ -n "$SYS_BODY" ]; then
    ok "syslog: a capture frame carries the request id"
    echo "$SYS_BODY" | grep -q '<redacted:8 bytes>' && ok "syslog: Authorization is <redacted:8 bytes>" || fail "syslog: no <redacted:8 bytes>"
    echo "$SYS_BODY" | grep -q '<redacted:3 bytes>' && ok "syslog: Cookie is <redacted:3 bytes>" || fail "syslog: no <redacted:3 bytes>"
    echo "$SYS_BODY" | grep -q 'Bearer x' && fail "syslog: the bearer value leaked" || ok "syslog: the bearer value is absent"
else
    fail "syslog: no capture frame for $RED_RID"
fi
ACCESS_BODY=$(syslog_body access "\"request_id\":\"$RED_RID\"")
if [ -n "$ACCESS_BODY" ]; then
    ok "syslog: the access frame with the same request id exists (the join)"
    assert_json "$ACCESS_BODY" '.status' '502' 'syslog: the access row agrees on the status'
    assert_json "$ACCESS_BODY" '.client_ip' "$(echo "$SYS_BODY" | jq -r '.client_ip')" 'syslog: the access row agrees on client_ip'
    assert_json "$ACCESS_BODY" '.timestamp' "$(echo "$SYS_BODY" | jq -r '.timestamp')" 'syslog: the access row agrees on timestamp'
else
    fail "syslog: no access frame for $RED_RID"
fi

# OTLP: one JSON line per export batch; the record body is a string.
OTLP_LINE=""
for _ in $(seq 1 30); do
    OTLP_LINE=$(grep "$RED_RID" "$OTLP_LOG" 2>/dev/null | grep 'capture' | head -1 || true)
    [ -n "$OTLP_LINE" ] && break
    sleep 1
done
if [ -n "$OTLP_LINE" ]; then
    ok "OTLP: a capture record carries the request id"
    # The collector's file exporter is Go's JSON encoder, which writes
    # `<` and `>` as < and >; the marker is matched without them.
    echo "$OTLP_LINE" | grep -q 'redacted:8 bytes' && ok "OTLP: Authorization is <redacted:8 bytes>" || fail "OTLP: no <redacted:8 bytes>"
    echo "$OTLP_LINE" | grep -q 'redacted:3 bytes' && ok "OTLP: Cookie is <redacted:3 bytes>" || fail "OTLP: no <redacted:3 bytes>"
    grep -q 'Bearer x' "$OTLP_LOG" && fail "OTLP: the bearer value leaked" || ok "OTLP: the bearer value is absent from the whole file"
    grep "$RED_RID" "$OTLP_LOG" | grep -q '\\"kind\\":\\"access\\"' \
        && ok "OTLP: the access record with the same request id exists (the join)" \
        || fail "OTLP: no access record for $RED_RID"
else
    fail "OTLP: no capture record for $RED_RID in $OTLP_LOG"
    tail -c 800 "$OTLP_LOG" 2>/dev/null || true
fi

# ---------------------------------------------------------------------
# Roles: Operator disables and cannot create; Viewer cannot read the ring.
# ---------------------------------------------------------------------
log "=== roles: Operator and Viewer on the capture surface ==="
OP_PW="CaptureOperator!4242"
VIEW_PW="CaptureViewer!424242"
assert_json "$(api_post /api/v1/users "{\"username\":\"cap-op\",\"password\":\"$OP_PW\",\"role\":\"operator\"}")" '.data.role' 'operator' 'operator account created'
assert_json "$(api_post /api/v1/users "{\"username\":\"cap-view\",\"password\":\"$VIEW_PW\",\"role\":\"viewer\"}")" '.data.role' 'viewer' 'viewer account created'
ADMIN_SESSION="$SESSION"
OP_SESSION=$(login_as cap-op "$OP_PW")
VIEW_SESSION=$(login_as cap-view "$VIEW_PW")
[ -n "$OP_SESSION" ] && [ -n "$VIEW_SESSION" ] && ok "both accounts log in" || fail "operator/viewer login failed"

SESSION="$OP_SESSION"
assert_status POST "$API/api/v1/capture/rules" 403 "an Operator cannot POST a rule" \
    -H "Content-Type: application/json" -d "{\"name\":\"nope\",\"route_id\":\"$ROUTE_R\",\"emit\":{\"always\":true}}"
assert_status GET "$API/api/v1/capture/rules/$RULE5" 403 "an Operator cannot read one rule"
assert_status GET "$API/api/v1/capture/rules" 200 "an Operator can list the rules"
# The role check runs in middleware, ahead of the handler that refuses
# the supervisor's empty ring, so an Operator is let through either way
# and the code that comes back is the node's, not the role's.
if [ "$WORKERS_MODE" = true ]; then
    assert_status GET "$API/api/v1/capture/recent" 503 "an Operator reaches the ring and the workers node refuses it"
else
    assert_status GET "$API/api/v1/capture/recent" 200 "an Operator can read the ring"
fi
OP_DISABLE=$(api_post "/api/v1/capture/rules/$RULE5/disable" '{}')
assert_json "$OP_DISABLE" '.data.enabled' 'false' 'an Operator can POST .../disable'
assert_json "$OP_DISABLE" '.data.id' "$RULE5" 'the disable answers with the rule'

SESSION="$VIEW_SESSION"
assert_status GET "$API/api/v1/capture/recent" 403 "a Viewer cannot read the ring"
assert_status GET "$API/api/v1/capture/rules" 403 "a Viewer cannot list the rules"
assert_status POST "$API/api/v1/capture/rules/$RULE5/disable" 403 "a Viewer cannot disable a rule"
SESSION="$ADMIN_SESSION"
settle

# ---------------------------------------------------------------------
# Story 10.2 IV2: the directory sink, read-only then writable.
# ---------------------------------------------------------------------
log "=== 10.2 IV2: output.dir on a read-only mount ==="
mk_rule "{\"name\":\"ro dir\",\"route_id\":\"$ROUTE_R\",\"emit\":{\"always\":true},\"limits\":{\"max_captures\":100,\"rate_per_minute\":100,\"ttl_seconds\":3600},\"output\":{\"dir\":\"$CAPTURE_RO_DIR\"}}"; RULE6="$RULE_ID"
[ -n "$RULE6" ] && ok "rule with output.dir $CAPTURE_RO_DIR created (id=$RULE6)" || fail "rule create: $RULE_OUT"
settle
DROPPED_BEFORE=$(metric_dropped_sink "$RULE6")
NON_2XX=0
for n in 1 2 3 4 5; do
    px "$PROXY_IN" "$HOST_R" /ok -X POST -H 'Content-Type: application/json' -d "{\"ro\":$n}"
    [ "$PX_CODE" = "200" ] || NON_2XX=$((NON_2XX+1))
done
[ "$NON_2XX" = "0" ] && ok "5/5 requests answered 200 with the sink on a read-only mount" \
    || fail "$NON_2XX/5 requests did not answer 200"
wait_ring "$RULE6" 5 && ok "the five records still reached the ring" || fail "ring has $(ring_count_for_rule "$RULE6") records for the rule, expected 5"
DROPPED_AFTER=0
for _ in $(seq 1 15); do
    DROPPED_AFTER=$(metric_dropped_sink "$RULE6")
    [ "${DROPPED_AFTER:-0}" -ge 5 ] && break
    sleep 1
done
if [ "${DROPPED_AFTER:-0}" -ge 5 ] && [ "${DROPPED_AFTER:-0}" -gt "${DROPPED_BEFORE:-0}" ]; then
    ok "lorica_captures_total{outcome=\"dropped_sink\"} moved for the rule ($DROPPED_BEFORE -> $DROPPED_AFTER)"
else
    fail "dropped_sink for the rule is '$DROPPED_AFTER' (was '$DROPPED_BEFORE'), expected at least 5"
fi
disable_rule "$RULE6"

log "=== 10.2 IV2: output.dir on a writable directory ==="
mk_rule "{\"name\":\"rw dir\",\"route_id\":\"$ROUTE_R\",\"emit\":{\"always\":true},\"limits\":{\"max_captures\":100,\"rate_per_minute\":100,\"ttl_seconds\":3600},\"output\":{\"dir\":\"$CAPTURE_DIR\"}}"; RULE7="$RULE_ID"
[ -n "$RULE7" ] && ok "rule with output.dir $CAPTURE_DIR created (id=$RULE7)" || fail "rule create: $RULE_OUT"
settle
declare -a RW_IDS=()
for n in 1 2 3; do
    px "$PROXY_IN" "$HOST_R" /ok -X POST -H 'Content-Type: application/json' -d "{\"rw\":$n}"
    [ "$PX_CODE" = "200" ] || fail "rw POST /ok #$n answered $PX_CODE"
    RW_IDS+=("$(px_request_id)")
done
FILES=0
for _ in $(seq 1 20); do
    FILES=$(find "$CAPTURE_DIR" -maxdepth 1 -name '*.json' 2>/dev/null | wc -l | tr -d ' ')
    [ "$FILES" -ge 3 ] && break
    sleep 1
done
[ "$FILES" = "3" ] && ok "one file per capture: 3 files in $CAPTURE_DIR" || fail "$FILES file(s) in $CAPTURE_DIR, expected 3"
[ "$(find "$CAPTURE_DIR" -maxdepth 1 -name '.*.tmp' 2>/dev/null | wc -l | tr -d ' ')" = "0" ] \
    && ok "no temporary file left behind" || fail "temporary files left in $CAPTURE_DIR"
for RID in "${RW_IDS[@]}"; do
    FILE=$(find "$CAPTURE_DIR" -maxdepth 1 -name "*-${RID}.json" | head -1)
    if [ -z "$FILE" ]; then
        fail "no file named *-${RID}.json"
        continue
    fi
    NAME=$(basename "$FILE")
    echo "$NAME" | grep -qE "^[0-9]{8}T[0-9]{6}\.[0-9]{9}Z-${RID}\.json$" \
        && ok "$NAME is <timestamp>-<request_id>.json" || fail "$NAME is not the documented name shape"
    MODE=$(stat -c '%a' "$FILE")
    [ "$MODE" = "640" ] && ok "$NAME has mode 0640" || fail "$NAME has mode $MODE, expected 640"
    DL=$(mktemp)
    download_record "$RID" "$RULE7" "$DL"
    if [ "$(sha256sum < "$FILE" | awk '{print $1}')" = "$(sha256sum < "$DL" | awk '{print $1}')" ]; then
        ok "$NAME is byte-identical to the ring download"
    else
        fail "$NAME differs from the ring download ($(wc -c < "$FILE") vs $(wc -c < "$DL") bytes)"
    fi
    # The download's own headers only exist when the record came from
    # the endpoint; on a workers node it came from the stdout sink,
    # because the endpoint answers 503 there and the file name is
    # asserted against the sink's own naming above.
    if [ "$WORKERS_MODE" = false ]; then
        assert_header_value "$(cat "$DL_HEADERS")" "Content-Disposition" "attachment; filename=\"$NAME\"" \
            "the download is served under the same file name"
    fi
    # The name's stamp is the record's UTC timestamp in basic ISO 8601
    # with nine fractional digits: strip the offset, drop `-` and `:`,
    # right-pad the fraction with zeros.
    TS=$(jq -r '.timestamp' "$DL")
    TS_BASE="${TS%%+*}"
    TS_BASE="${TS_BASE%Z}"
    TS_WHOLE=$(echo "${TS_BASE%%.*}" | tr -d ':-')
    TS_FRAC=""
    case "$TS_BASE" in *.*) TS_FRAC="${TS_BASE#*.}" ;; esac
    STAMP="${TS_WHOLE}.$(printf '%-9s' "$TS_FRAC" | tr ' ' '0')Z"
    [ "${NAME%%-*}" = "$STAMP" ] && ok "$NAME carries the record's own timestamp" \
        || fail "$NAME does not start with the record's timestamp ($STAMP from $TS)"
    rm -f "$DL" "$DL_HEADERS"
done
disable_rule "$RULE7"

# ---------------------------------------------------------------------
# Story 10.2 IV3: a binary body round-trips through base64.
# ---------------------------------------------------------------------
log "=== 10.2 IV3: application/octet-stream through base64 ==="
mk_rule "{\"name\":\"binary\",\"route_id\":\"$ROUTE_R\",\"emit\":{\"always\":true},\"limits\":{\"max_captures\":100,\"rate_per_minute\":100,\"ttl_seconds\":3600}}"; RULE8="$RULE_ID"
[ -n "$RULE8" ] && ok "binary rule created (id=$RULE8)" || fail "rule create: $RULE_OUT"
settle
RAW=$(mktemp)
head -c 32768 /dev/urandom > "$RAW"
px "$PROXY_IN" "$HOST_R" /ok -X POST -H 'Content-Type: application/octet-stream' --data-binary "@$RAW"
[ "$PX_CODE" = "200" ] && ok "the binary POST answered 200" || fail "the binary POST answered $PX_CODE"
assert_json "$PX_BODY" '.body_length' '32768' 'the upstream received the 32 768 bytes'
BIN_RID=$(px_request_id)
wait_ring "$RULE8" 1 || fail "no record for the binary exchange"
BIN_REC=$(mktemp)
download_record "$BIN_RID" "$RULE8" "$BIN_REC"
assert_json "$(cat "$BIN_REC")" '.request.body_encoding' 'base64' 'the request body is base64'
assert_json "$(cat "$BIN_REC")" '.request.truncated' 'false' 'the request body is not truncated'
assert_json "$(cat "$BIN_REC")" '.request.body_bytes_total' '32768' 'body_bytes_total is 32 768'
DECODED=$(mktemp)
jq -r '.request.body' "$BIN_REC" | base64 -d > "$DECODED" 2>/dev/null || true
if [ "$(sha256sum < "$RAW" | awk '{print $1}')" = "$(sha256sum < "$DECODED" | awk '{print $1}')" ]; then
    ok "the base64 body decodes byte for byte to the original"
else
    fail "the decoded body differs from the original ($(wc -c < "$DECODED") bytes decoded)"
fi
assert_json "$(cat "$BIN_REC")" '.response.body_encoding' 'utf8' 'the JSON response body is utf8'
rm -f "$RAW" "$BIN_REC" "$DECODED"
disable_rule "$RULE8"

# ---------------------------------------------------------------------
# Story 10.2 IV4: the redaction list is additive.
# ---------------------------------------------------------------------
log "=== 10.2 IV4: redact.headers [X-Api-Key] adds, never subtracts ==="
mk_rule "{\"name\":\"x-api-key\",\"route_id\":\"$ROUTE_R\",\"emit\":{\"always\":true},\"limits\":{\"max_captures\":100,\"rate_per_minute\":100,\"ttl_seconds\":3600},\"redact\":{\"headers\":[\"X-Api-Key\"]}}"; RULE9="$RULE_ID"
[ -n "$RULE9" ] && ok "rule naming X-Api-Key created (id=$RULE9)" || fail "rule create: $RULE_OUT"
settle
px "$PROXY_IN" "$HOST_R" /ok -X POST -H 'Content-Type: application/json' \
    -H 'X-Api-Key: k-123' -H 'Authorization: Bearer abc' -H 'X-Plain: visible' -d '{}'
[ "$PX_CODE" = "200" ] || fail "the X-Api-Key POST answered $PX_CODE"
KEY_RID=$(px_request_id)
wait_ring "$RULE9" 1 || fail "no record for the X-Api-Key exchange"
KEY_REC=$(mktemp)
download_record "$KEY_RID" "$RULE9" "$KEY_REC"
[ "$(hdr "$KEY_REC" x-api-key)" = "<redacted:5 bytes>" ] && ok "X-Api-Key reads <redacted:5 bytes>" \
    || fail "X-Api-Key reads '$(hdr "$KEY_REC" x-api-key)'"
[ "$(hdr "$KEY_REC" authorization)" = "<redacted:10 bytes>" ] && ok "Authorization still reads <redacted:10 bytes>" \
    || fail "Authorization reads '$(hdr "$KEY_REC" authorization)'"
[ "$(hdr "$KEY_REC" x-plain)" = "visible" ] && ok "a header the rule does not name is kept verbatim" \
    || fail "X-Plain reads '$(hdr "$KEY_REC" x-plain)'"
rm -f "$KEY_REC"
disable_rule "$RULE9"

# ---------------------------------------------------------------------
# Audit C1: a WAF block is captured with the WAF's status.
# ---------------------------------------------------------------------
log "=== audit C1: a WAF block on a 4xx rule ==="
mk_rule "{\"name\":\"waf 4xx\",\"route_id\":\"$ROUTE_W\",\"emit\":{\"status\":[\"client_error\"]},\"limits\":{\"max_captures\":100,\"rate_per_minute\":100,\"ttl_seconds\":3600}}"; RULE10="$RULE_ID"
[ -n "$RULE10" ] && ok "rule with status [client_error] on the WAF route created (id=$RULE10)" || fail "rule create: $RULE_OUT"
settle
px "$PROXY_IN" "$HOST_W" "/search?q=1%27%20OR%201%3D1--"
[ "$PX_CODE" = "403" ] && ok "the WAF blocked the SQLi probe (403)" || fail "the SQLi probe answered $PX_CODE, expected 403"
wait_ring "$RULE10" 1 && ok "the block produced a record" || fail "no record for the WAF block"
WAF_REC=$(ring | jq -c --arg r "$RULE10" '[(.data.captures // [])[] | select(.rule_id == $r)] | .[0]')
[ "$(ring_count_for_rule "$RULE10")" = "1" ] && ok "exactly one record for the block" || fail "$(ring_count_for_rule "$RULE10") records, expected 1"
assert_json "$WAF_REC" '.response.status' '403' "the record's response.status is the WAF's 403"
assert_json "$WAF_REC" '.request.body_skipped' 'null' 'request.body_skipped is null'
assert_json "$WAF_REC" '.request.uri' '/search?q=1%27%20OR%201%3D1--' 'the record carries the probe uri'
assert_json "$WAF_REC" '.route_id' "$ROUTE_W" 'the record names the WAF route'
disable_rule "$RULE10"

# ---------------------------------------------------------------------
# Story 10.1 IV3, the clock: disabled within 130 s of creation.
# ---------------------------------------------------------------------
log "=== 10.1 IV3: ttl_seconds 120 clears enabled within 130 s ==="
TTL_DISABLED_AT=""
while :; do
    if [ "$(rule_get "$RULE_TTL" | jq -r '.data.enabled')" = "false" ]; then
        TTL_DISABLED_AT=$(date +%s)
        break
    fi
    [ $(( $(date +%s) - TTL_T0 )) -ge 130 ] && break
    sleep 2
done
if [ -n "$TTL_DISABLED_AT" ]; then
    ok "the ttl rule read enabled=false $((TTL_DISABLED_AT - TTL_T0)) s after creation"
else
    fail "the ttl rule is still enabled 130 s after creation"
fi
ROWS=""
for _ in $(seq 1 10); do
    ROWS=$(audit_rows capture.rule.auto_disabled "$RULE_TTL")
    [ "$(echo "$ROWS" | jq 'length')" -ge 1 ] && break
    sleep 1
done
# Every process that enforces capture runs the expiry sweep, and the
# store's own `enabled = 1` filter is what keeps a second sweeper from
# auditing the same rule twice; under `--workers` two sweepers can still
# race for it, so the count is bounded by the worker count rather than
# pinned at one.
ROW_COUNT=$(echo "$ROWS" | jq 'length')
if [ "${ROW_COUNT:-0}" -ge 1 ] && [ "${ROW_COUNT:-0}" -le "$CAPTURE_WORKERS" ]; then
    ok "$ROW_COUNT capture.rule.auto_disabled row(s) name the ttl rule"
else
    fail "$ROW_COUNT auto_disabled row(s) for the ttl rule, expected between 1 and $CAPTURE_WORKERS"
fi
# The audited instant is `to_rfc3339()`, offset spelled `+00:00`; the
# API serialises the same DateTime<Utc> and spells it that way too, so
# the value is used as is, with a `Z` rewritten only if one appears.
case "$TTL_EXPIRES_AT" in
    *Z) EXPIRES_STORED="${TTL_EXPIRES_AT%Z}+00:00" ;;
    *)  EXPIRES_STORED="$TTL_EXPIRES_AT" ;;
esac
EXPECTED=$(jq -nc --arg r "$ROUTE_R" --arg id "$RULE_TTL" --arg e "$EXPIRES_STORED" '{budget:"expired",enabled:false,expires_at:$e,route_id:$r,rule_id:$id}')
ROW_HASH=$(echo "$ROWS" | jq -r '.[0].after_payload_hash // ""')
if [ "$ROW_HASH" = "$(sha256_of "$EXPECTED")" ]; then
    ok "the audit payload says budget=expired with the rule's expires_at"
else
    fail "the audit payload hash '$ROW_HASH' is not that of $EXPECTED"
fi
ROW_TS=$(echo "$ROWS" | jq -r '.[0].timestamp // ""')
LAG=$(python3 -c 'import sys,datetime
def p(s):
    return datetime.datetime.fromisoformat(s.strip().replace("Z","+00:00"))
try:
    print(int((p(sys.argv[1]) - p(sys.argv[2])).total_seconds()))
except Exception as e:
    print("nan")' "$ROW_TS" "$TTL_EXPIRES_AT")
if [ "$LAG" != "nan" ] && [ "$LAG" -ge 0 ] && [ "$LAG" -le 10 ]; then
    ok "the audit row was written ${LAG} s after expires_at"
else
    fail "the audit row timestamp '$ROW_TS' is ${LAG} s from expires_at '$TTL_EXPIRES_AT'"
fi

# The rule is never deleted, only disabled.
[ "$(api_get /api/v1/capture/rules | jq -r --arg id "$RULE_TTL" '[(.data.rules // [])[] | select(.id == $id)] | length')" = "1" ] \
    && ok "the expired rule is still listed, disabled, not deleted" || fail "the expired rule vanished from the listing"

capture_helpers_cleanup

# --- Summary ---
log "=== capture smoke: summary ==="
echo "Tests: $TOTAL | Passed: $PASS | Failed: $FAIL"
if [ "$FAIL" -gt 0 ]; then
    exit 1
fi
exit 0
