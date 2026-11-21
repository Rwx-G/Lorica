#!/usr/bin/env bash
# =============================================================================
# Lorica MCP E2E smoke (Story 11.4 AC #4, IV1, IV2).
#
# A real node, a real automation listener, and a client driving each
# tier over stdio: this script spawns `lorica-mcp` as a coprocess and
# writes newline-delimited JSON-RPC to its stdin, the way an operator's
# MCP client does. What it asserts:
#
#   - each tier's token is minted by `lorica mcp token create --tier`,
#     the real CLI, and taken from its stdout alone;
#   - `server/discover` answers the revision the binary announces, and
#     `tools/list` lists exactly the tools the CLI's blast radius printed
#     for that tier (the expected list is read off the CLI's stderr, not
#     retyped here). Both are computed by one rule, `Tier::registers`,
#     so this proves the printed blast radius and the served list agree
#     end to end, through the real mint and the real server. It cannot
#     see the tier half of that rule (`Tier::serves`), which removes
#     nothing for a token the tier check accepts and is a tripwire the
#     unit tests hold, not something this run exercises;
#   - one mutation per mutating tier (config: a route inside the
#     hostname grant; admin: `access_log_retention` raised, its safe
#     direction), one refusal each (a hostname outside the grant; the
#     same setting lowered), and a tool of another tier not callable,
#     with no row for it once a later row of the same session landed;
#   - the audit row of each call: the principal and the request line are
#     what the node established, the transport and the tool sit inside
#     the `asserted[...]` clause, because over stdio they are the
#     caller's claim;
#   - one revocation mid-session: the next call fails with the plane's
#     401 and a `token_revoked` row, and a fresh start is refused;
#   - IV1 end to end: a token carrying logs:read and routes:write, minted
#     by `lorica automation token create`, makes lorica-mcp exit 78
#     naming both scopes;
#   - IV2: the audit chain verifies afterwards.
#
# It runs from the Lorica image, sharing the node's network namespace
# (see the `mcp-smoke` service in docker-compose.yml for why). The
# stdio session, the CLI mint, JSON through sqlite3 and the audit row
# checks live in mcp-helpers.sh, shared with the cluster MCP phase.
# =============================================================================

# `-u` without `-e`, unlike the other smokes: this one captures the
# exit code of commands that are expected to fail (the IV1 refusal, a
# revoked token's restart) and asserts on it, which `-e` would abort.
set -u
# A write to a lorica-mcp that died would raise SIGPIPE and kill the
# shell before `print_results`, losing every line collected so far. A
# broken write fails the call it belongs to instead.
trap '' PIPE

source /tests/helpers.sh
source /tests/mcp-helpers.sh

SHARED="${SHARED_DIR:-/shared}"
MANAGEMENT_PORT=19443
API="https://127.0.0.1:${MANAGEMENT_PORT}"
ENDPOINT="https://127.0.0.1:9446"
CA_BUNDLE="$SHARED/automation-listener-ca.pem"
PASSWORD_FILE="$SHARED/admin_password"
GRANTED_PATTERN="*.mcp.example.com"
GRANTED_HOST="app.mcp.example.com"
OUTSIDE_HOST="app.outside.example.org"
BACKEND_CIDR="192.0.2.0/24"
WORK=$(mktemp -d)

# The exit codes lorica-mcp documents (lorica-mcp/src/main.rs).
EXIT_MISCONFIGURED=78
EXIT_PLANE_UNREACHABLE=69

# ---------------------------------------------------------------------
# Minting through the CLI (`mint_tier` lives in mcp-helpers.sh).
# ---------------------------------------------------------------------

# The stored row of the token labelled $1, as the management API lists
# it: the node's own record of what it minted.
token_row() {
    json "$(api_get /api/v1/automation/tokens)" \
        "SELECT e.value FROM d, json_each(d.doc, '\$.data.tokens') e
         WHERE e.value->>'name' = '$1' ORDER BY e.value->>'created_at' DESC LIMIT 1"
}

# The tools the CLI's blast radius names, one per line, sorted.
blast_radius_tools() {
    grep -oE '^    lorica_[a-z_]+ \[' "$1" | awk '{print $1}' | sort
}

# $1 tier, then the grant flags. Mints, asserts the CLI's contract, and
# leaves TOKEN, PUBLIC_ID and EXPECTED_TOOLS behind.
mint_and_check() {
    local tier="$1" row scopes_row scopes_printed
    shift
    mint_tier "$tier" "$@"
    if [ "$MINT_CODE" = "0" ]; then
        ok "[$tier] lorica mcp token create --tier $tier exited 0"
    else
        fail "[$tier] lorica mcp token create --tier $tier exited $MINT_CODE: $(tail -c 400 "$MINT_ERR")"
    fi
    if [ "$(printf '%s\n' "$MINTED" | wc -l)" = "1" ] && [[ "$MINTED" =~ ^[[:graph:]]+$ ]]; then
        ok "[$tier] stdout carries one line and nothing but the token"
    else
        fail "[$tier] stdout is not a single token line"
    fi
    TOKEN="$MINTED"

    row=$(token_row "mcp-$tier")
    PUBLIC_ID=$(json "$row" "SELECT doc->>'public_id' FROM d")
    if [ -n "$PUBLIC_ID" ] && grep -q "minted automation token $PUBLIC_ID" "$MINT_ERR"; then
        ok "[$tier] the node stored mcp-$tier as $PUBLIC_ID, the id the CLI printed on stderr"
    else
        fail "[$tier] no stored row mcp-$tier matching the CLI's notice (row: '$row')"
    fi

    # The scopes the node stored against the ones the CLI said it minted.
    scopes_row=$(json "$row" "SELECT value FROM d, json_each(d.doc, '\$.scopes') ORDER BY 1" | tr '\n' ' ')
    scopes_printed=$(sed -n 's/^  Scopes: //p' "$MINT_ERR" | tr ',' '\n' | tr -d ' ' | sed '/^$/d' | sort | tr '\n' ' ')
    if [ -n "$scopes_row" ] && [ "$scopes_row" = "$scopes_printed" ]; then
        ok "[$tier] the stored scopes are the ones the blast radius printed ($scopes_row)"
    else
        fail "[$tier] stored scopes '$scopes_row' differ from printed '$scopes_printed'"
    fi

    EXPECTED_TOOLS=$(blast_radius_tools "$MINT_ERR")
    if [ -z "$EXPECTED_TOOLS" ]; then
        fail "[$tier] the blast radius named no tool"
    fi
}

# $1 tier label. Discovery, then the tool list against the blast radius.
check_discovery_and_tools() {
    local tier="$1" listed
    if [ -n "$REVISION" ]; then
        ok "[$tier] lorica-mcp started and announced revision $REVISION on stderr"
    else
        fail "[$tier] lorica-mcp announced no revision: $(tail -c 400 "$SESSION_ERR")"
    fi
    if grep -q "Token $PUBLIC_ID registered" "$SESSION_ERR"; then
        ok "[$tier] the startup notice names the token $PUBLIC_ID"
    else
        fail "[$tier] the startup notice does not name $PUBLIC_ID: $(tail -c 400 "$SESSION_ERR")"
    fi

    rpc server/discover ""
    if [ "$(answer_field '$.result.supportedVersions')" = "[\"$REVISION\"]" ] \
        && [ "$(answer_field '$.result.serverInfo.name')" = "lorica-mcp" ]; then
        ok "[$tier] server/discover answers lorica-mcp speaking $REVISION alone"
    else
        fail "[$tier] server/discover answered: $RPC_ANSWER"
    fi

    rpc tools/list ""
    listed=$(json "$RPC_ANSWER" "SELECT e.value->>'name' FROM d, json_each(d.doc, '\$.result.tools') e ORDER BY 1")
    if [ -n "$listed" ] && [ "$listed" = "$EXPECTED_TOOLS" ]; then
        ok "[$tier] tools/list is exactly the blast radius's $(echo "$listed" | wc -l) tools"
    else
        fail "[$tier] tools/list differs from the blast radius: listed [$(echo $listed)] expected [$(echo $EXPECTED_TOOLS)]"
    fi
}

# $1 tier label, $2 a tool of another tier. The tool does not exist to be
# called: a protocol error, no result, and nothing reaches the plane,
# which `assert_no_row_for` checks once a later row has landed.
check_foreign_tool() {
    local tier="$1" tool="$2"
    call_tool "$tool" '{}'
    if [ -n "$(answer_field '$.error.code')" ] && [ -z "$(answer_field '$.result')" ]; then
        ok "[$tier] $tool, of another tier, is a protocol error ($(answer_field '$.error.code'))"
    else
        fail "[$tier] $tool answered: $RPC_ANSWER"
    fi
}

# ---------------------------------------------------------------------
# Audit rows.
# ---------------------------------------------------------------------

# $1 operator, $2 tool, $3 label. No request row names the tool for the
# operator. Rows are queued and land in order, so this is called after
# `assert_audit` has seen a LATER row of the same token land: a row for
# the refused call, had one been written, would be there by then.
assert_no_row_for() {
    if [ "$(audit_count "$1" "%" "%tool=$2%")" = "0" ]; then
        ok "$3: the refused $2 left no row: it never reached the plane"
    else
        fail "$3: a row names $2 for $1"
    fi
}

route_count() {
    json "$(api_get /api/v1/routes)" \
        "SELECT count(*) FROM d, json_each(d.doc, '\$.data.routes') e WHERE e.value->>'hostname' = '$1'"
}

setting_value() {
    json "$(api_get /api/v1/settings)" "SELECT doc->>'\$.data.$1' FROM d"
}

# ---------------------------------------------------------------------
# Preflight.
# ---------------------------------------------------------------------
log "=== mcp smoke: preflight ==="

for _ in $(seq 1 120); do
    [ -f "$SHARED/mcp_ready" ] && break
    sleep 1
done
if [ ! -f "$SHARED/mcp_ready" ]; then
    fail "the mcp node never became ready"
    print_results
fi
if ! wait_for_api 60; then
    fail "the management API never answered"
    print_results
fi
login "$(cat "$PASSWORD_FILE")"
if [ -n "$(api_get /api/v1/settings | grep -o '"data"')" ]; then
    ok "logged in to the management API"
else
    fail "cannot log in to the management API"
    print_results
fi

# The listener opens with the process; a handful of probes at most, well
# inside the per-source connection budget.
LISTENER_UP=0
for _ in $(seq 1 15); do
    code=$(curl -s --cacert "$CA_BUNDLE" -o /dev/null -w '%{http_code}' \
        "$ENDPOINT/automation/v1/whoami" 2>/dev/null || true)
    if [ -n "$code" ] && [ "$code" != "000" ]; then
        LISTENER_UP=1
        break
    fi
    sleep 2
done
if [ "$LISTENER_UP" = "1" ]; then
    ok "the automation listener answers on $ENDPOINT, verified against the node's own certificate"
else
    fail "the automation listener never answered on $ENDPOINT"
    print_results
fi

# ---------------------------------------------------------------------
# Read tier, and the revocation.
# ---------------------------------------------------------------------
log "=== mcp smoke: read tier ==="
mint_and_check read
READ_OPERATOR="mcp-read ($PUBLIC_ID)"
READ_PUBLIC_ID="$PUBLIC_ID"
READ_TOKEN="$TOKEN"

start_session "$READ_TOKEN" read
check_discovery_and_tools read

call_tool lorica_routes '{}'
if [ "$(answer_field '$.result.isError')" = "0" ]; then
    ok "[read] lorica_routes answered"
else
    fail "[read] lorica_routes answered: $RPC_ANSWER"
fi
assert_audit "$READ_OPERATOR" "automation.request.ok" "GET /automation/v1/routes" lorica_routes "[read] the read"

check_foreign_tool read lorica_route_create

log "=== mcp smoke: revocation mid-session ==="
assert_status DELETE "$API/api/v1/automation/tokens/$READ_PUBLIC_ID" 200 "[read] the token was revoked"
call_tool lorica_routes '{}'
REVOKED_TEXT=$(answer_field '$.result.content[0].text')
if [ "$(answer_field '$.result.isError')" = "1" ] && [[ "$REVOKED_TEXT" == *"HTTP 401"* ]]; then
    ok "[read] the next call is an execution error carrying the plane's 401"
else
    fail "[read] the call after revocation answered: $RPC_ANSWER"
fi
# A refused credential names nobody: the row's principal is the plane's
# anonymous marker and the reason rides in the action.
assert_audit "-" "automation.request.unauthenticated:token_revoked" \
    "GET /automation/v1/routes" lorica_routes "[read] the refused call"
assert_no_row_for "$READ_OPERATOR" lorica_route_create "[read]"
end_session
if [ "$SESSION_CODE" = "0" ]; then
    ok "[read] closing stdin ended the session with exit 0"
else
    fail "[read] the session ended with exit $SESSION_CODE"
fi

REVOKED_ERR="$WORK/mcp-revoked.err"
REVOKED_OUT=$(LORICA_MCP_ENDPOINT="$ENDPOINT" LORICA_MCP_TOKEN="$READ_TOKEN" \
    LORICA_MCP_CA_BUNDLE="$CA_BUNDLE" lorica-mcp </dev/null 2>"$REVOKED_ERR")
REVOKED_CODE=$?
if [ "$REVOKED_CODE" = "$EXIT_PLANE_UNREACHABLE" ] && [ -z "$REVOKED_OUT" ]; then
    ok "[read] a fresh start on the revoked token exits $EXIT_PLANE_UNREACHABLE with nothing on stdout"
else
    fail "[read] a fresh start on the revoked token exited $REVOKED_CODE: $(tail -c 400 "$REVOKED_ERR")"
fi

# ---------------------------------------------------------------------
# Config tier.
# ---------------------------------------------------------------------
log "=== mcp smoke: config tier ==="
mint_and_check config --hostname "$GRANTED_PATTERN" --backend-cidr "$BACKEND_CIDR"
CONFIG_OPERATOR="mcp-config ($PUBLIC_ID)"

start_session "$TOKEN" config
check_discovery_and_tools config
check_foreign_tool config lorica_settings_update

call_tool lorica_route_create "{\"route\":{\"hostname\":\"$GRANTED_HOST\"}}"
if [ "$(answer_field '$.result.isError')" = "0" ] && [ "$(route_count "$GRANTED_HOST")" = "1" ]; then
    ok "[config] lorica_route_create inside the grant created $GRANTED_HOST"
else
    fail "[config] lorica_route_create answered: $RPC_ANSWER"
fi
assert_audit "$CONFIG_OPERATOR" "automation.request.ok" "POST /automation/v1/routes" \
    lorica_route_create "[config] the mutation"

call_tool lorica_route_create "{\"route\":{\"hostname\":\"$OUTSIDE_HOST\"}}"
OUTSIDE_TEXT=$(answer_field '$.result.content[0].text')
if [ "$(answer_field '$.result.isError')" = "1" ] \
    && [[ "$OUTSIDE_TEXT" == *"outside this token's allowed_hostnames"* ]] \
    && [ "$(route_count "$OUTSIDE_HOST")" = "0" ]; then
    ok "[config] a hostname outside the grant is refused by the plane and nothing is created"
else
    fail "[config] the out-of-grant create answered: $RPC_ANSWER"
fi
assert_audit "$CONFIG_OPERATOR" "automation.request.forbidden" "POST /automation/v1/routes" \
    lorica_route_create "[config] the refusal"
assert_no_row_for "$CONFIG_OPERATOR" lorica_settings_update "[config]"
end_session
if [ "$SESSION_CODE" = "0" ]; then
    ok "[config] closing stdin ended the session with exit 0"
else
    fail "[config] the session ended with exit $SESSION_CODE"
fi

# ---------------------------------------------------------------------
# Admin tier.
# ---------------------------------------------------------------------
log "=== mcp smoke: admin tier ==="
mint_and_check admin
ADMIN_OPERATOR="mcp-admin ($PUBLIC_ID)"

start_session "$TOKEN" admin
check_discovery_and_tools admin
check_foreign_tool admin lorica_route_create

RETENTION_BEFORE=$(setting_value access_log_retention)
RETENTION_RAISED=$((RETENTION_BEFORE + 1000))
call_tool lorica_settings_update "{\"settings\":{\"access_log_retention\":$RETENTION_RAISED}}"
if [ "$(answer_field '$.result.isError')" = "0" ] \
    && [ "$(setting_value access_log_retention)" = "$RETENTION_RAISED" ]; then
    ok "[admin] access_log_retention raised from $RETENTION_BEFORE to $RETENTION_RAISED"
else
    fail "[admin] raising access_log_retention answered: $RPC_ANSWER"
fi
assert_audit "$ADMIN_OPERATOR" "automation.request.ok" "PUT /automation/v1/settings" \
    lorica_settings_update "[admin] the mutation"

call_tool lorica_settings_update "{\"settings\":{\"access_log_retention\":$RETENTION_BEFORE}}"
LOWER_TEXT=$(answer_field '$.result.content[0].text')
if [ "$(answer_field '$.result.isError')" = "1" ] && [[ "$LOWER_TEXT" == *"access_log_retention"* ]] \
    && [ "$(setting_value access_log_retention)" = "$RETENTION_RAISED" ]; then
    ok "[admin] lowering a raise-only retention is refused by the plane, naming the field"
else
    fail "[admin] lowering access_log_retention answered: $RPC_ANSWER"
fi
assert_audit "$ADMIN_OPERATOR" "automation.request.refused" "PUT /automation/v1/settings" \
    lorica_settings_update "[admin] the refusal"
assert_no_row_for "$ADMIN_OPERATOR" lorica_route_create "[admin]"
end_session
if [ "$SESSION_CODE" = "0" ]; then
    ok "[admin] closing stdin ended the session with exit 0"
else
    fail "[admin] the session ended with exit $SESSION_CODE"
fi

# ---------------------------------------------------------------------
# IV1: one process, one tier, end to end.
# ---------------------------------------------------------------------
log "=== mcp smoke: IV1, a token spanning two tiers ==="
IV1_ERR="$WORK/iv1-mint.err"
IV1_TOKEN=$(lorica --management-port "$MANAGEMENT_PORT" automation token create \
    --name mcp-iv1-spans --scope logs:read --scope routes:write \
    --hostname "$GRANTED_HOST" --backend-cidr "$BACKEND_CIDR" \
    --password-file "$PASSWORD_FILE" 2>"$IV1_ERR")
IV1_MINT_CODE=$?
if [ "$IV1_MINT_CODE" = "0" ] && [ -n "$IV1_TOKEN" ]; then
    ok "[iv1] lorica automation token create minted logs:read + routes:write"
else
    fail "[iv1] the mint exited $IV1_MINT_CODE: $(tail -c 400 "$IV1_ERR")"
fi
IV1_RUN_ERR="$WORK/iv1-run.err"
IV1_OUT=$(LORICA_MCP_ENDPOINT="$ENDPOINT" LORICA_MCP_TOKEN="$IV1_TOKEN" \
    LORICA_MCP_CA_BUNDLE="$CA_BUNDLE" lorica-mcp </dev/null 2>"$IV1_RUN_ERR")
IV1_CODE=$?
if [ "$IV1_CODE" = "$EXIT_MISCONFIGURED" ] && [ -z "$IV1_OUT" ]; then
    ok "[iv1] lorica-mcp refused to start with exit $EXIT_MISCONFIGURED and nothing on stdout"
else
    fail "[iv1] lorica-mcp exited $IV1_CODE: $(tail -c 400 "$IV1_RUN_ERR")"
fi
if grep -q "logs:read" "$IV1_RUN_ERR" && grep -q "routes:write" "$IV1_RUN_ERR"; then
    ok "[iv1] the refusal names both logs:read and routes:write"
else
    fail "[iv1] the refusal does not name both scopes: $(tail -c 600 "$IV1_RUN_ERR")"
fi

# ---------------------------------------------------------------------
# IV2: the audit chain verifies after all of it.
# ---------------------------------------------------------------------
log "=== mcp smoke: IV2, audit chain ==="
VERIFY=$(api_get /api/v1/audit/verify)
VERIFIED=$(json "$VERIFY" "SELECT json_extract(doc, '\$.data.verified') FROM d")
LOCAL_ROWS=$(json "$VERIFY" "SELECT e.value->>'total_rows' FROM d, json_each(d.doc, '\$.data.nodes') e WHERE e.value->>'node_id' = ''")
if [ "$VERIFIED" = "1" ] && [ "${LOCAL_ROWS:-0}" -gt 0 ] 2>/dev/null; then
    ok "[iv2] the audit chain verifies over $LOCAL_ROWS rows"
else
    fail "[iv2] audit verify answered: $VERIFY"
fi

# ---------------------------------------------------------------------
# Streams (Story 12.10 Lot H and Story 12.7 IV2, delivered by Story
# 12.12 Lot J). Two scenarios, each printing its one L4-SCENARIO line
# (Story 12.12 D-c) at the end of the section:
#
#   12.10-iv1-dashboard-stream-visible-read-only
#       a stream created with the body the dashboard's form sends is
#       bound, read by a read-tier token on both automation paths and
#       through the two MCP read tools, absent from the config and admin
#       tool lists, unwritable by a token holding every scope, its
#       backend undeletable by a token, and audited as the session's.
#       PARTIAL by Story 12.12 D-d: the form's request is posted, not
#       clicked in a browser;
#   12.7-iv2-template-yes-payload-no
#       a token with backends:write sets a health-check template on the
#       automation API and through the MCP config tier, and a raw
#       send/expect payload is refused on both, nothing stored.
#
# Tokens and backends this section creates are named `l4j-`; the stream
# carries the fixture's own name.
# ---------------------------------------------------------------------
log "=== mcp smoke: streams (Story 12.10 IV1, Story 12.7 IV2) ==="
J_IV1=12.10-iv1-dashboard-stream-visible-read-only
J_IV2=12.7-iv2-template-yes-payload-no
J_PARTIAL_NOTE="the create is the request body the dashboard's stream form sends (the Story 12.10 Lot D2 fixture), not a browser click"
declare -A J_FAILED=()
declare -A J_NOTE=()

j_ok() { ok "[$1] $2"; }
j_fail() {
    fail "[$1] $2"
    J_FAILED[$1]="${J_FAILED[$1]:+${J_FAILED[$1]}; }$2"
}
j_note() { J_NOTE[$1]="${J_NOTE[$1]:+${J_NOTE[$1]}; }$2"; }

# Every CLI mint logs in with --password-file, and the management API
# admits five logins a minute from one address (LOGIN_MAX in
# lorica-api/src/middleware/rate_limit.rs): the login and the four
# mints above use the window up. A mint refused with the limit's 429 is
# retried once the window has rolled, within 100 s.
j_login_limited() { [ "$1" != "0" ] && grep -q '429 Too Many Requests' "$2"; }
j_mint_tier() {
    local _
    for _ in $(seq 1 10); do
        mint_tier "$@"
        j_login_limited "$MINT_CODE" "$MINT_ERR" || return 0
        sleep 10
    done
}
# $1 name, $2 the verdict a clean run reports (PASS or PARTIAL).
j_line() {
    local name="$1" status="$2" detail
    detail="${J_NOTE[$name]:--}"
    if [ -n "${J_FAILED[$name]:-}" ]; then
        status=FAIL
        detail="${J_FAILED[$name]}"
    fi
    printf 'L4-SCENARIO %s %s %s\n' "$name" "$status" "$(printf '%s' "$detail" | tr '\r\n\t' '   ')"
}

# $1 token, $2 method, $3 path, $4 optional JSON body. The token rides
# in a header file, never in argv. Leaves AUTO_CODE and AUTO_BODY.
auto_call() {
    local header="$WORK/l4j-bearer" out="$WORK/l4j-auto.out"
    (umask 077; printf 'Authorization: Bearer %s\n' "$1" > "$header")
    if [ -n "${4:-}" ]; then
        AUTO_CODE=$(curl -s --cacert "$CA_BUNDLE" -o "$out" -w '%{http_code}' -H @"$header" \
            -H 'Content-Type: application/json' -X "$2" -d "$4" "$ENDPOINT$3" 2>/dev/null)
    else
        AUTO_CODE=$(curl -s --cacert "$CA_BUNDLE" -o "$out" -w '%{http_code}' -H @"$header" \
            -X "$2" "$ENDPOINT$3" 2>/dev/null)
    fi
    AUTO_BODY=$(cat "$out" 2>/dev/null)
    rm -f "$header"
}

# $1 method, $2 path, $3 body. Leaves MGMT_CODE and MGMT_BODY.
mgmt_call() {
    local out="$WORK/l4j-mgmt.out"
    MGMT_CODE=$(curl -sk -b "$SESSION" -o "$out" -w '%{http_code}' -X "$1" \
        -H 'Content-Type: application/json' ${3:+-d "$3"} "$API$2" 2>/dev/null)
    MGMT_BODY=$(cat "$out" 2>/dev/null)
}

backend_check() {
    json "$(api_get "/api/v1/backends/$1")" \
        "SELECT (doc->>'\$.data.health_check.kind') || ':' || coalesce(doc->>'\$.data.health_check.template', '-') FROM d"
}

backends_at() {
    json "$(api_get /api/v1/backends)" \
        "SELECT count(*) FROM d, json_each(d.doc, '\$.data.backends') e WHERE e.value->>'address' = '$1'"
}

# Whether $1 (a port) has a listening TCP socket in this network
# namespace: what `ss -ltn` reads, from /proc, since the Lorica image
# carries no iproute2.
tcp_listening() {
    local hex
    hex=$(printf '%04X' "$1")
    cat /proc/net/tcp /proc/net/tcp6 2>/dev/null \
        | awk -v port=":$hex" '$2 ~ port"$" && $4 == "0A" {found=1} END {exit !found}'
}

# Leaves in STREAM_TOOLS the tool names of the session's tools/list that
# name a stream, and in TOOL_COUNT how many tools it lists. Not run in a
# command substitution: `rpc` advances the session's request id.
list_stream_tools() {
    rpc tools/list ""
    STREAM_TOOLS=$(json "$RPC_ANSWER" "SELECT e.value->>'name' FROM d, json_each(d.doc, '\$.result.tools') e
                        WHERE e.value->>'name' LIKE '%stream%' ORDER BY 1" | tr '\n' ' ')
    TOOL_COUNT=$(json "$RPC_ANSWER" "SELECT json_array_length(doc, '\$.result.tools') FROM d")
}

# The Story 12.10 Lot D2 fixture, `lorica-dashboard/frontend/src/lib/
# stream-iv1-create.json`, byte for byte: the body the stream form sends
# for a create with only a name, a port and one backend. The smoke
# runs with only tests-e2e-docker/ mounted, so it carries a copy; the
# drawer's Vitest suite pins the form to the file.
IV1_FIXTURE='{
  "name": "iv1-tcp",
  "protocol": "tcp",
  "listen_address": "0.0.0.0",
  "port_first": 40100,
  "backend_ids": ["<BACKEND_ID>"]
}'
IV1_NAME=iv1-tcp
IV1_PORT=40100
IV1_BACKEND_ADDR="192.0.2.30:7000"
IV2_TEMPLATE_ADDR="192.0.2.41:6379"
IV2_PAYLOAD_ADDR="192.0.2.42:6379"
RAW_CHECK='{"kind":"tcp_send_expect","send":{"text":"PING\r\n"},"expect":[{"match":"prefix","bytes":{"text":"+PONG"}}]}'

# ---- 12.10 IV1: the create, as the dashboard sends it ----------------
mgmt_call POST /api/v1/backends \
    "{\"name\":\"l4j-iv1-backend\",\"address\":\"$IV1_BACKEND_ADDR\",\"health_check_enabled\":false}"
IV1_BID=$(json "$MGMT_BODY" "SELECT doc->>'\$.data.id' FROM d")
mgmt_call POST /api/v1/streams "${IV1_FIXTURE//<BACKEND_ID>/$IV1_BID}"
IV1_SID=$(json "$MGMT_BODY" "SELECT doc->>'\$.data.id' FROM d")
if [ -n "$IV1_BID" ] && [ "$MGMT_CODE" = "201" ] && [ -n "$IV1_SID" ]; then
    j_ok "$J_IV1" "a management session created $IV1_NAME from the form's body (HTTP 201)"
else
    j_fail "$J_IV1" "the form's create answered HTTP $MGMT_CODE: $(printf '%s' "$MGMT_BODY" | head -c 300)"
fi

LISTENING=0
for _ in $(seq 1 25); do
    if tcp_listening "$IV1_PORT"; then
        LISTENING=1
        break
    fi
    sleep 0.2
done
if [ "$LISTENING" = 1 ]; then
    j_ok "$J_IV1" "port $IV1_PORT listens on the node"
else
    j_fail "$J_IV1" "nothing listens on port $IV1_PORT 5 s after the create"
fi

# ---- A read-tier token: both automation paths -------------------------
j_mint_tier read --name l4j-read
READ2_TOKEN="$MINTED"
if [ "$MINT_CODE" = "0" ] && [ -n "$READ2_TOKEN" ]; then
    j_ok "$J_IV1" "lorica mcp token create --tier read minted l4j-read"
else
    j_fail "$J_IV1" "the read-tier mint exited $MINT_CODE: $(tail -c 300 "$MINT_ERR")"
fi

auto_call "$READ2_TOKEN" GET "/automation/v1/streams?name=$IV1_NAME"
LISTED=$(json "$AUTO_BODY" "SELECT count(*) FROM d, json_each(d.doc, '\$.data.items') e WHERE e.value->>'id' = '$IV1_SID'")
if [ "$AUTO_CODE" = "200" ] && [ "$LISTED" = "1" ]; then
    j_ok "$J_IV1" "GET /automation/v1/streams lists $IV1_NAME to the read-tier token"
else
    j_fail "$J_IV1" "GET /automation/v1/streams answered HTTP $AUTO_CODE: $(printf '%s' "$AUTO_BODY" | head -c 300)"
fi

auto_call "$READ2_TOKEN" GET "/automation/v1/streams/status?name=$IV1_NAME"
BIND=$(json "$AUTO_BODY" "SELECT e.value->>'\$.bind.state' FROM d, json_each(d.doc, '\$.data.items') e WHERE e.value->>'id' = '$IV1_SID'")
if [ "$AUTO_CODE" = "200" ] && [ "$BIND" = "bound" ]; then
    j_ok "$J_IV1" "GET /automation/v1/streams/status reads $IV1_NAME with bind.state bound"
else
    j_fail "$J_IV1" "GET /automation/v1/streams/status answered HTTP $AUTO_CODE, bind '$BIND': $(printf '%s' "$AUTO_BODY" | head -c 300)"
fi

# ---- The read-tier MCP session: both stream tools ---------------------
start_session "$READ2_TOKEN" l4j-read
call_tool lorica_streams "{\"name\":\"$IV1_NAME\"}"
STREAMS_TEXT=$(answer_field '$.result.content[0].text')
if [ "$(answer_field '$.result.isError')" = "0" ] && [[ "$STREAMS_TEXT" == *"$IV1_SID"* ]]; then
    j_ok "$J_IV1" "lorica_streams lists $IV1_NAME in the read tier"
else
    j_fail "$J_IV1" "lorica_streams answered: $(printf '%s' "$RPC_ANSWER" | head -c 300)"
fi
call_tool lorica_stream_status "{\"name\":\"$IV1_NAME\"}"
STATUS_TEXT=$(answer_field '$.result.content[0].text')
if [ "$(answer_field '$.result.isError')" = "0" ] && [[ "$STATUS_TEXT" == *"$IV1_SID"* ]] \
    && [[ "$STATUS_TEXT" == *bound* ]]; then
    j_ok "$J_IV1" "lorica_stream_status reads $IV1_NAME bound in the read tier"
else
    j_fail "$J_IV1" "lorica_stream_status answered: $(printf '%s' "$RPC_ANSWER" | head -c 300)"
fi
end_session

# ---- The config and admin tiers: no stream tool -----------------------
j_mint_tier admin --name l4j-admin
start_session "$MINTED" l4j-admin
list_stream_tools
ADMIN_STREAM_TOOLS="$STREAM_TOOLS"
ADMIN_TOOL_COUNT="$TOOL_COUNT"
end_session

j_mint_tier config --name l4j-config --hostname "$GRANTED_PATTERN" --backend-cidr "$BACKEND_CIDR"
CONFIG2_TOKEN="$MINTED"
CONFIG2_PUBLIC_ID=$(json "$(token_row l4j-config)" "SELECT doc->>'public_id' FROM d")
CONFIG2_OPERATOR="l4j-config ($CONFIG2_PUBLIC_ID)"
start_session "$CONFIG2_TOKEN" l4j-config
list_stream_tools
CONFIG_STREAM_TOOLS="$STREAM_TOOLS"
CONFIG_TOOL_COUNT="$TOOL_COUNT"
# A tool count above zero keeps an empty list from passing for a failed
# tools/list.
if [ -n "$CONFIG2_PUBLIC_ID" ] && [ -z "$CONFIG_STREAM_TOOLS" ] && [ -z "$ADMIN_STREAM_TOOLS" ] \
    && [ "${CONFIG_TOOL_COUNT:-0}" -gt 0 ] && [ "${ADMIN_TOOL_COUNT:-0}" -gt 0 ]; then
    j_ok "$J_IV1" "the config ($CONFIG_TOOL_COUNT tools) and admin ($ADMIN_TOOL_COUNT tools) tiers list no stream tool"
else
    j_fail "$J_IV1" "stream tools listed: config [$CONFIG_STREAM_TOOLS] of $CONFIG_TOOL_COUNT, admin [$ADMIN_STREAM_TOOLS] of $ADMIN_TOOL_COUNT (config token '$CONFIG2_PUBLIC_ID')"
fi

# A token cannot unlink a backend from a stream (Story 12.10 D-i): the
# refusal lists the stream by id, since a config-tier token cannot hold
# streams:read.
call_tool lorica_backend_delete "{\"id\":\"$IV1_BID\"}"
DELETE_TEXT=$(answer_field '$.result.content[0].text')
mgmt_call GET "/api/v1/backends/$IV1_BID"
if [ "$(answer_field '$.result.isError')" = "1" ] && [[ "$DELETE_TEXT" == *"$IV1_SID"* ]] \
    && [[ "$DELETE_TEXT" == *"streams:read"* ]] && [ "$MGMT_CODE" = "200" ]; then
    j_ok "$J_IV1" "lorica_backend_delete on the stream's backend is refused listing the stream's id; the backend stays"
else
    j_fail "$J_IV1" "lorica_backend_delete answered: $(printf '%s' "$RPC_ANSWER" | head -c 300) (backend GET HTTP $MGMT_CODE)"
fi

# ---- 12.7 IV2, the MCP config tier -------------------------------------
# The template backend is created on the automation API first, by the
# same token, so both halves work on one row.
auto_call "$CONFIG2_TOKEN" POST /automation/v1/backends \
    "{\"address\":\"$IV2_TEMPLATE_ADDR\",\"health_check\":{\"kind\":\"tcp_template\",\"template\":\"redis_ping\"}}"
IV2_BID=$(json "$AUTO_BODY" "SELECT doc->>'\$.data.id' FROM d")
if [ "$AUTO_CODE" = "201" ] && [ -n "$IV2_BID" ] && [ "$(backend_check "$IV2_BID")" = "tcp_template:redis_ping" ]; then
    j_ok "$J_IV2" "POST /automation/v1/backends with tcp_template redis_ping is created (HTTP 201) and stored as sent"
else
    j_fail "$J_IV2" "the template create answered HTTP $AUTO_CODE: $(printf '%s' "$AUTO_BODY" | head -c 300)"
fi

auto_call "$CONFIG2_TOKEN" POST /automation/v1/backends \
    "{\"address\":\"$IV2_PAYLOAD_ADDR\",\"health_check\":$RAW_CHECK}"
if [ "$AUTO_CODE" = "403" ] && [[ "$AUTO_BODY" == *health_check* ]] \
    && [ "$(backends_at "$IV2_PAYLOAD_ADDR")" = "0" ]; then
    j_ok "$J_IV2" "POST /automation/v1/backends with a raw send/expect payload is refused (HTTP 403) naming health_check, nothing stored"
else
    j_fail "$J_IV2" "the payload create answered HTTP $AUTO_CODE ($(backends_at "$IV2_PAYLOAD_ADDR") stored): $(printf '%s' "$AUTO_BODY" | head -c 300)"
fi

auto_call "$CONFIG2_TOKEN" PUT "/automation/v1/backends/$IV2_BID" "{\"health_check\":$RAW_CHECK}"
if [ "$AUTO_CODE" = "403" ] && [ "$(backend_check "$IV2_BID")" = "tcp_template:redis_ping" ]; then
    j_ok "$J_IV2" "PUT /automation/v1/backends/{id} to a raw payload is refused (HTTP 403), the template kept"
else
    j_fail "$J_IV2" "the payload update answered HTTP $AUTO_CODE, stored $(backend_check "$IV2_BID"): $(printf '%s' "$AUTO_BODY" | head -c 300)"
fi

UPDATE_ROWS_BEFORE=$(audit_count "$CONFIG2_OPERATOR" "automation.request.%" "%tool=lorica_backend_update%")
call_tool lorica_backend_update "{\"id\":\"$IV2_BID\",\"backend\":{\"health_check\":$RAW_CHECK}}"
REFUSED_ERROR=$(answer_field '$.error.message')
REFUSED_TEXT=$(answer_field '$.result.content[0].text')
if { [ -n "$(answer_field '$.error.code')" ] || [ "$(answer_field '$.result.isError')" = "1" ]; } \
    && [[ "$REFUSED_ERROR $REFUSED_TEXT" == *send* ]] \
    && [ "$(backend_check "$IV2_BID")" = "tcp_template:redis_ping" ]; then
    j_ok "$J_IV2" "lorica_backend_update with a payload is refused by the tool naming send, the template kept"
else
    j_fail "$J_IV2" "lorica_backend_update with a payload answered: $(printf '%s' "$RPC_ANSWER" | head -c 300)"
fi

call_tool lorica_backend_update "{\"id\":\"$IV2_BID\",\"backend\":{\"health_check\":{\"kind\":\"tcp_template\",\"template\":\"smtp_banner\"}}}"
if [ "$(answer_field '$.result.isError')" = "0" ] && [ "$(backend_check "$IV2_BID")" = "tcp_template:smtp_banner" ]; then
    j_ok "$J_IV2" "lorica_backend_update to tcp_template smtp_banner is applied"
else
    j_fail "$J_IV2" "lorica_backend_update with a template answered: $(printf '%s' "$RPC_ANSWER" | head -c 300) (stored $(backend_check "$IV2_BID"))"
fi
# Rows land in order: once the applied update's row is there, a row for
# the refused one would be too. Exactly one row means the refusal never
# reached the plane.
assert_audit "$CONFIG2_OPERATOR" "automation.request.ok" "PUT /automation/v1/backends/$IV2_BID" \
    lorica_backend_update "[$J_IV2] the applied template update"
UPDATE_ROWS_AFTER=$(audit_count "$CONFIG2_OPERATOR" "automation.request.%" "%tool=lorica_backend_update%")
if [ "$UPDATE_ROWS_AFTER" = "$((UPDATE_ROWS_BEFORE + 1))" ]; then
    j_ok "$J_IV2" "the refused payload left no audit row: it never reached the plane"
else
    j_fail "$J_IV2" "lorica_backend_update rows went from $UPDATE_ROWS_BEFORE to $UPDATE_ROWS_AFTER (one expected)"
fi
end_session
j_note "$J_IV2" "backends:write token: tcp_template created (201) and updated through the MCP config tier; raw send/expect refused on POST and PUT (403) and by the MCP tool naming send, nothing stored, no plane call"

# ---- A token holding every scope cannot write a stream -----------------
EVERY_ERR="$WORK/l4j-every.err"
# settings:write refuses a lifetime past seven days, so the mint names one.
for _ in $(seq 1 10); do
    EVERY_TOKEN=$(lorica --management-port "$MANAGEMENT_PORT" automation token create \
        --name l4j-every \
        --scope environments:write --scope environments:read --scope routes:read \
        --scope certificates:read --scope logs:read --scope waf:read --scope sla:read \
        --scope cluster:read --scope backends:read --scope streams:read \
        --scope routes:write --scope backends:write --scope certificates:write \
        --scope settings:write \
        --hostname "$GRANTED_HOST" --backend-cidr "$BACKEND_CIDR" \
        --lifetime-days 1 \
        --password-file "$PASSWORD_FILE" 2>"$EVERY_ERR")
    j_login_limited "$?" "$EVERY_ERR" || break
    sleep 10
done
if [ -z "$EVERY_TOKEN" ]; then
    j_fail "$J_IV1" "the every-scope mint failed: $(tail -c 300 "$EVERY_ERR")"
fi
# The 403 body says the path declares no scope; `no_declared_scope` is
# the refusal's reason, carried by its audit row's action
# (docs/automation.md, the reasons table).
EVERY_PUBLIC_ID=$(json "$(token_row l4j-every)" "SELECT doc->>'public_id' FROM d")
EVERY_OPERATOR="l4j-every ($EVERY_PUBLIC_ID)"
WRITES_REFUSED=""
for request in "POST /automation/v1/streams" "PUT /automation/v1/streams" "DELETE /automation/v1/streams" \
    "PUT /automation/v1/streams/$IV1_SID" "DELETE /automation/v1/streams/$IV1_SID"; do
    method=${request%% *}
    path=${request#* }
    auto_call "$EVERY_TOKEN" "$method" "$path" '{}'
    if [ "$AUTO_CODE" = "403" ] && [[ "$AUTO_BODY" == *"declares no automation scope"* ]]; then
        WRITES_REFUSED="$WRITES_REFUSED $method"
    else
        j_fail "$J_IV1" "$request with every scope answered HTTP $AUTO_CODE: $(printf '%s' "$AUTO_BODY" | head -c 200)"
    fi
done
REFUSED_ROWS=0
for _ in $(seq 1 10); do
    REFUSED_ROWS=$(audit_count "$EVERY_OPERATOR" "automation.request.forbidden:no_declared_scope" "% /automation/v1/streams%")
    [ "${REFUSED_ROWS:-0}" -ge 5 ] 2>/dev/null && break
    sleep 1
done
if [ "$WRITES_REFUSED" = " POST PUT DELETE PUT DELETE" ] && [ "$REFUSED_ROWS" = "5" ]; then
    j_ok "$J_IV1" "a token holding every scope gets 403 on POST, PUT and DELETE of /automation/v1/streams[/{id}], five rows automation.request.forbidden:no_declared_scope"
else
    j_fail "$J_IV1" "every-scope stream writes refused:[$WRITES_REFUSED], no_declared_scope rows by '$EVERY_OPERATOR': '$REFUSED_ROWS' (5 expected)"
fi
mgmt_call GET "/api/v1/streams/$IV1_SID"
[ "$MGMT_CODE" = "200" ] || j_fail "$J_IV1" "the stream is gone after the refused writes (HTTP $MGMT_CODE)"

# ---- The audit: the session's create, and the chain ---------------------
CREATE_ROWS=$(json "$(api_get "/api/v1/audit?action=stream.create&limit=500")" \
    "SELECT count(*) FROM d, json_each(d.doc, '\$.data.entries') e
     WHERE e.value->>'action' = 'stream.create' AND e.value->>'target_id' = '$IV1_SID'
       AND e.value->>'operator_username' = 'admin' AND e.value->>'operator_role' <> 'automation'")
VERIFY=$(api_get /api/v1/audit/verify)
VERIFIED=$(json "$VERIFY" "SELECT json_extract(doc, '\$.data.verified') FROM d")
if [ "$CREATE_ROWS" = "1" ] && [ "$VERIFIED" = "1" ]; then
    j_ok "$J_IV1" "the audit holds stream.create for $IV1_SID by the admin session, and the chain verifies"
else
    j_fail "$J_IV1" "stream.create rows by the session: '$CREATE_ROWS'; audit verify: $(printf '%s' "$VERIFY" | head -c 200)"
fi
j_note "$J_IV1" "$J_PARTIAL_NOTE; the stream bound on :$IV1_PORT, read on /automation/v1/streams and /streams/status (bound) and by lorica_streams and lorica_stream_status, no stream tool in the config and admin tiers, writes 403 for an every-scope token with five no_declared_scope audit rows, backend delete refused listing the stream id, stream.create audited to the session, chain verified"

j_line "$J_IV1" PARTIAL
j_line "$J_IV2" PASS

print_results
