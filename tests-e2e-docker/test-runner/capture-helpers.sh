#!/usr/bin/env bash
# =============================================================================
# Readers shared by the two traffic-capture smokes (v1.8.0 Epic 10).
#
# Both of them have to read capture records out of the collectors rather
# than out of the API: the syslog collector writes RFC 6587 octet-counted
# frames with no separator, and on a `--workers` node the recent-captures
# ring is unreachable (it is per worker and the management API runs in
# the supervisor), so the node's own stdout is the only place the records
# are. Two small Python parsers do the walking; this file owns them so
# the two smokes share one copy.
#
# Source AFTER SYSLOG_LOG and LORICA_LOG are set; the readers take the
# paths from those globals at call time. Call `capture_helpers_cleanup`
# before exiting.
# =============================================================================

# Walk the octet-counted syslog file. Usage:
#   python3 $FRAMES FILE MSGID NEEDLE        -> prints the match count
#   python3 $FRAMES FILE MSGID NEEDLE body   -> prints the first match's
#                                               JSON body
FRAMES=$(mktemp)
cat > "$FRAMES" <<'PYEOF'
import sys

path, msgid, needle = sys.argv[1:4]
want_body = len(sys.argv) > 4 and sys.argv[4] == "body"
try:
    with open(path, "rb") as handle:
        data = handle.read()
except OSError:
    data = b""
pos = 0
count = 0
first_body = None
while pos < len(data):
    space = data.find(b" ", pos)
    if space < 0:
        break
    try:
        length = int(data[pos:space])
    except ValueError:
        break
    message = data[space + 1:space + 1 + length]
    pos = space + 1 + length
    parts = message.split(b" ", 6)
    if len(parts) < 7 or parts[5].decode("ascii", "replace") != msgid:
        continue
    if needle.encode("utf-8") not in message:
        continue
    count += 1
    if first_body is None:
        rest = parts[6]
        close = rest.find(b"] ")
        first_body = rest[close + 2:] if close >= 0 else rest
if want_body:
    sys.stdout.write((first_body or b"").decode("utf-8", "replace"))
else:
    print(count)
PYEOF

syslog_count() { python3 "$FRAMES" "$SYSLOG_LOG" "$1" "$2"; }
syslog_body()  { python3 "$FRAMES" "$SYSLOG_LOG" "$1" "$2" body; }

# Read the records out of the node's own stdout, the always-on
# `lorica::capture` sink. Usage:
#   python3 $RECORDS FILE              -> the ring's listing shape,
#                                         newest first
#   python3 $RECORDS FILE REQ [RULE]   -> the newest matching record's
#                                         document, as the exact text
#                                         the sinks received
# The log is JSON (`--log-format json`, the default), one event per
# line, with the document in the `record` field as a string. A partial
# last line while the node is still writing is skipped, not fatal.
RECORDS=$(mktemp)
cat > "$RECORDS" <<'PYEOF'
import json
import sys

path = sys.argv[1]
want_request = sys.argv[2] if len(sys.argv) > 2 else None
want_rule = sys.argv[3] if len(sys.argv) > 3 else None

found = []
try:
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for line in handle:
            if '"lorica::capture"' not in line:
                continue
            try:
                event = json.loads(line)
            except ValueError:
                continue
            fields = event.get("fields")
            text = fields.get("record") if isinstance(fields, dict) else None
            if not isinstance(text, str):
                text = event.get("record")
            if not isinstance(text, str):
                continue
            try:
                document = json.loads(text)
            except ValueError:
                continue
            found.append((text, document))
except OSError:
    pass

found.reverse()  # newest first, the order the ring lists in
if want_request is None:
    json.dump({"data": {"captures": [doc for _, doc in found]}}, sys.stdout)
else:
    for text, document in found:
        if document.get("request_id") != want_request:
            continue
        if want_rule and document.get("rule_id") != want_rule:
            continue
        sys.stdout.write(text)
        break
PYEOF

# Every record on the node's stdout, in the ring listing's shape.
stdout_records() { python3 "$RECORDS" "$LORICA_LOG"; }
# The exact document text of one record: $1 request id, $2 rule id
# (optional). Empty when the node emitted no such record.
stdout_record_text() { python3 "$RECORDS" "$LORICA_LOG" "$1" "${2:-}"; }
# How many records one rule produced, read from stdout.
stdout_count_for_rule() {
    stdout_records | jq -r --arg r "$1" '[(.data.captures // [])[] | select(.rule_id == $r)] | length'
}

capture_helpers_cleanup() { rm -f "$FRAMES" "$RECORDS"; }

# ---------------------------------------------------------------------
# The proxy, login and capture-rule helpers both capture smokes use.
# ---------------------------------------------------------------------

resolve_v4() { getent hosts "$1" | awk '{print $1}' | head -1; }
in_cidr() {
    python3 -c 'import ipaddress,sys; sys.exit(0 if ipaddress.ip_address(sys.argv[1]) in ipaddress.ip_network(sys.argv[2]) else 1)' "$1" "$2"
}

# login_as <username> <password> -> echoes "lorica_session=..." or "".
login_as() {
    local username="$1" password="$2"
    local headers http
    headers=$(mktemp)
    http=$(curl -s -o /dev/null -D "$headers" -w '%{http_code}' \
        "$API/api/v1/auth/login" -X POST \
        -H "Content-Type: application/json" \
        -d "{\"username\":\"$username\",\"password\":\"$password\"}")
    if [ "$http" = "200" ]; then
        grep -i 'Set-Cookie:' "$headers" | grep -o 'lorica_session=[^;]*' | head -1
    fi
    rm -f "$headers"
}

# One request through the proxy. $1 proxy base, $2 Host, $3 path, then
# extra curl args. Leaves PX_CODE and PX_BODY behind.
PX_CODE=""
PX_BODY=""
px() {
    local proxy="$1" host="$2" path="$3"
    shift 3
    local body_file
    body_file=$(mktemp)
    PX_CODE=$(curl -s --max-time 120 -o "$body_file" -w '%{http_code}' \
        -H "Host: $host" "$@" "${proxy}${path}" 2>/dev/null || echo "000")
    PX_BODY=$(cat "$body_file")
    rm -f "$body_file"
}
# The request id the proxy injected upstream, echoed by the backend.
px_request_id() { echo "$PX_BODY" | jq -r '.received_headers["x-request-id"] // empty'; }

# Create a capture rule from a JSON body. Leaves RULE_ID ("" on refusal)
# and RULE_OUT (the response) behind; globals, not an echo, so the
# response survives (a command substitution would run it in a subshell).
RULE_ID=""
RULE_OUT=""
mk_rule() {
    RULE_OUT=$(api_post /api/v1/capture/rules "$1")
    RULE_ID=$(echo "$RULE_OUT" | jq -r '.data.id // empty')
}
rule_get() { api_get "/api/v1/capture/rules/$1"; }
