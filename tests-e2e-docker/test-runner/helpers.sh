#!/usr/bin/env bash
# Shared test helpers for Lorica e2e tests

PASS=0
FAIL=0
TOTAL=0
SESSION=""

log()   { echo -e "\033[1;34m[TEST]\033[0m $*"; }
ok()    { PASS=$((PASS+1)); TOTAL=$((TOTAL+1)); echo -e "\033[1;32m  PASS\033[0m $*"; }
fail()  { FAIL=$((FAIL+1)); TOTAL=$((TOTAL+1)); echo -e "\033[1;31m  FAIL\033[0m $*"; }

api_get()  { curl -sf -b "$SESSION" "$API$1" 2>/dev/null; }
api_post() { curl -sf -b "$SESSION" -X POST -H "Content-Type: application/json" -d "$2" "$API$1" 2>/dev/null; }
api_put()  { curl -sf -b "$SESSION" -X PUT -H "Content-Type: application/json" -d "$2" "$API$1" 2>/dev/null; }
api_del()  { curl -sf -b "$SESSION" -X DELETE "$API$1" 2>/dev/null; }

assert_status() {
    local method="$1" url="$2" expected="$3" label="$4"
    shift 4
    local status
    status=$(curl -s -o /dev/null -w '%{http_code}' -b "$SESSION" -X "$method" "$@" "$url" 2>/dev/null || true)
    if [ "$status" = "$expected" ]; then
        ok "$label (HTTP $status)"
    else
        fail "$label (expected $expected, got $status)"
    fi
}

assert_json() {
    local json="$1" path="$2" expected="$3" label="$4"
    local actual
    actual=$(echo "$json" | jq -r "$path" 2>/dev/null || echo "PARSE_ERROR")
    if [ "$actual" = "$expected" ]; then
        ok "$label"
    else
        fail "$label (expected '$expected', got '$actual')"
    fi
}

assert_json_gt() {
    local json="$1" path="$2" min="$3" label="$4"
    local actual
    actual=$(echo "$json" | jq -r "$path" 2>/dev/null || echo "0")
    if [ "$actual" -gt "$min" ] 2>/dev/null; then
        ok "$label (=$actual)"
    else
        fail "$label (expected >$min, got '$actual')"
    fi
}

assert_json_exists() {
    local json="$1" path="$2" label="$3"
    local actual
    actual=$(echo "$json" | jq -r "$path" 2>/dev/null || echo "null")
    if [ "$actual" != "null" ] && [ "$actual" != "" ]; then
        ok "$label (=$actual)"
    else
        fail "$label (field missing or null)"
    fi
}

assert_header_present() {
    local response_headers="$1" header_name="$2" label="$3"
    if echo "$response_headers" | grep -qi "^${header_name}:"; then
        ok "$label"
    else
        fail "$label (header '$header_name' not found)"
    fi
}

assert_header_absent() {
    local response_headers="$1" header_name="$2" label="$3"
    if echo "$response_headers" | grep -qi "^${header_name}:"; then
        fail "$label (header '$header_name' should not be present)"
    else
        ok "$label"
    fi
}

assert_header_value() {
    local response_headers="$1" header_name="$2" expected="$3" label="$4"
    local actual
    actual=$(echo "$response_headers" | grep -i "^${header_name}:" | head -1 | sed "s/^[^:]*: *//" | tr -d '\r')
    if [ "$actual" = "$expected" ]; then
        ok "$label"
    else
        fail "$label (expected '$expected', got '$actual')"
    fi
}

proxy_echo() {
    local host="$1" path="${2:-/echo}"
    shift 2
    curl -sf -H "Host: $host" "$@" "${PROXY}${path}" 2>/dev/null
}

proxy_echo_with_headers() {
    local host="$1" path="${2:-/echo}"
    shift 2
    curl -s -D - -H "Host: $host" "$@" "${PROXY}${path}" 2>/dev/null
}

wait_for_backend() {
    local addr="$1" max_wait="${2:-30}"
    for i in $(seq 1 "$max_wait"); do
        if curl -sf "http://$addr/healthz" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

wait_for_api() {
    local max_wait="${1:-120}"
    for i in $(seq 1 "$max_wait"); do
        if curl -sf "$API/api/v1/status" >/dev/null 2>&1; then
            return 0
        fi
        sleep 1
    done
    return 1
}

login() {
    local password="$1"
    SESSION=$(mktemp)
    curl -sf -c "$SESSION" -X POST -H "Content-Type: application/json" \
        -d "{\"username\":\"admin\",\"password\":\"$password\"}" \
        "$API/api/v1/auth/login" >/dev/null 2>&1
}

print_results() {
    echo ""
    echo "=============================="
    echo "  Results: $PASS passed, $FAIL failed ($TOTAL total)"
    echo "=============================="
    if [ "$FAIL" -gt 0 ]; then
        exit 1
    fi
}
