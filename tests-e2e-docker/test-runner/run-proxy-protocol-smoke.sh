#!/usr/bin/env bash
# =============================================================================
# Story 12.8 scenarios: PROXY protocol on the HTTP listeners (Story 12.12
# Lot H, the items of Story 12.8 Lot G).
#
# Called once at the end of an existing smoke, with that smoke's session:
#
#   SESSION="$SESSION" bash run-proxy-protocol-smoke.sh geoip    (run-geoip-smoke.sh)
#   SESSION="$SESSION" bash run-proxy-protocol-smoke.sh workers  (run-tests-workers.sh)
#
# `geoip` runs 12.8 IV1 and IV2 against the single-process node that has
# the MaxMind test database loaded (the geoip smoke set geoip_db_path and
# trusted_proxies 0.0.0.0/0 before this runs). `workers` runs IV2 again on
# the worker-mode node, since the PROXY settings reach the workers
# through the reload RPC. proxy_protocol_client.py stands in for the L4
# load balancer.
#
# Each scenario prints exactly one line for the L4 report (Story 12.12
# D-c): `L4-SCENARIO <name> <PASS|FAIL> <detail>`. Whatever happens, the
# PROXY settings are put back to off and the objects created here are
# deleted, so the rest of the profile is unaffected (12.8 IV3).
#
# Environment: LORICA_API, LORICA_PROXY (http://<node>:8080; the HTTPS
# listener is the same host on 8443), BACKEND1_ADDR, SESSION.
# =============================================================================
set -eu

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# helpers.sh resets SESSION: keep the caller's.
CALLER_SESSION="${SESSION:-}"
# shellcheck source=helpers.sh
source "$SCRIPT_DIR/helpers.sh"

PROFILE="${1:?usage: run-proxy-protocol-smoke.sh <geoip|workers>}"
API="${LORICA_API}"
PROXY="${LORICA_PROXY}"
BACKEND1="${BACKEND1_ADDR}"
SESSION="${CALLER_SESSION:?the calling smoke passes its session}"

NODE_HOST="${PROXY#*://}"
NODE_HOST="${NODE_HOST%%:*}"
HTTPS_TARGET="${NODE_HOST}:8443"
CLIENT="python3 $SCRIPT_DIR/proxy_protocol_client.py"

# Carried addresses. US and KR come from the GeoIP test database
# (run-geoip-smoke.sh lists its ranges); the others are documentation
# ranges absent from it.
IP_US="214.78.120.5"
IP_KR="2001:220::1"
IP_FORGED="192.0.2.99"
IP_CARRIED="198.51.100.20"
IP_RL_A="203.0.113.10"
IP_RL_B="203.0.113.11"
IP_RL_WARMUP="203.0.113.99"
# A trust list that holds no address of this runner (TEST-NET-1).
UNTRUSTED_CIDR="192.0.2.10/32"

# What a scenario creates, one `<kind> <id>` line each, in creation order:
# the scenarios run in subshells, so a variable would not reach the
# cleanup.
CREATED_FILE=$(mktemp)

# PROXY back to off, then routes before the certificates and the backend
# they reference.
pp_cleanup() {
    api_put /api/v1/settings '{"proxy_protocol_http":"off","proxy_protocol_https":"off","proxy_protocol_trusted_cidrs":[]}' >/dev/null || true
    local kind id
    for kind in routes certificates backends; do
        while read -r k id; do
            [ "$k" = "$kind" ] && { api_del "/api/v1/$kind/$id" >/dev/null || true; }
        done < "$CREATED_FILE"
    done
    : > "$CREATED_FILE"
}
trap 'pp_cleanup; rm -f "$CREATED_FILE"' EXIT

# ---- Helpers -----------------------------------------------------------

# `die <detail>` ends the running scenario with its FAIL line.
die() {
    echo "L4-SCENARIO ${SCENARIO} FAIL $*"
    echo FAIL >> "$VERDICT_FILE"
    exit 1
}

verdict_pass() {
    echo "L4-SCENARIO ${SCENARIO} PASS $*"
    echo PASS >> "$VERDICT_FILE"
}

# Run a scenario function in a subshell and print a FAIL line for it if
# it ended without a verdict. Returns 1 when it failed.
run_scenario() {
    SCENARIO="$1"
    VERDICT_FILE=$(mktemp)
    log "=== PROXY protocol: ${SCENARIO} (${PROFILE}) ==="
    local rc
    # The caller runs with errexit off and never from a conditional
    # context: bash ignores `set -e` inside anything run from one, this
    # subshell included.
    ( set -eu; "$2" )
    rc=$?
    if [ ! -s "$VERDICT_FILE" ]; then
        echo "L4-SCENARIO ${SCENARIO} FAIL ended without a verdict (exit ${rc})"
        rc=1
    elif grep -q FAIL "$VERDICT_FILE"; then
        rc=1
    fi
    rm -f "$VERDICT_FILE"
    return "$rc"
}

json_field() {
    printf '%s' "$1" | jq -r "$2"
}

# One request through the HTTPS listener. Usage:
#   https_request <host> <version 1|2|none> [<src>] [<dst>] [extra client args...]
https_request() {
    local host="$1" version="$2" src="${3:-203.0.113.7}" dst="${4:-192.0.2.1}"
    shift $(( $# < 4 ? $# : 4 ))
    $CLIENT request --target "$HTTPS_TARGET" --tls --sni "$host" --host "$host" \
        --version "$version" --src "$src" --dst "$dst" "$@"
}

# The carried destination must be of the source's family.
dst_for() {
    case "$1" in
        *:*) echo "2001:db8::1" ;;
        *) echo "192.0.2.1" ;;
    esac
}

# Prometheus value of a series selected by its name and label matchers
# (each a `label="value"` string), 0 when absent. Workers' counters reach
# the supervisor's /metrics through the per-worker aggregation.
metric_value() {
    local name="$1"
    shift
    local lines
    lines=$(curl -s -b "$SESSION" "$API/metrics" 2>/dev/null | grep "^${name}{" || true)
    local matcher
    for matcher in "$@"; do
        lines=$(printf '%s\n' "$lines" | grep -F "$matcher" || true)
    done
    printf '%s\n' "$lines" | awk 'NF { sum += $NF } END { printf "%d\n", sum + 0 }'
}

settings_put() {
    local out
    out=$(api_put /api/v1/settings "$1")
    if [ "$(json_field "$out" '.data.proxy_protocol_https // empty')" = "" ]; then
        die "settings refused: $out"
    fi
}

# Create the scenario's backend once, then a self-signed certificate and
# an HTTPS route for <host> with extra route JSON fields.
make_route() {
    local host="$1" extra="${2:-}" backend cert route id
    backend=$(awk '$1 == "backends" { print $2 }' "$CREATED_FILE")
    if [ -z "$backend" ]; then
        backend=$(json_field "$(api_post /api/v1/backends "{\"name\":\"pp-backend-${PROFILE}\",\"address\":\"${BACKEND1}\",\"health_check_enabled\":false}")" '.data.id // empty')
        [ -n "$backend" ] || die "backend create failed"
        echo "backends $backend" >> "$CREATED_FILE"
    fi
    cert=$(json_field "$(api_post /api/v1/certificates/self-signed "{\"domain\":\"${host}\"}")" '.data.id // empty')
    [ -n "$cert" ] || die "self-signed certificate for ${host} failed"
    echo "certificates $cert" >> "$CREATED_FILE"
    route=$(api_post /api/v1/routes "{\"hostname\":\"${host}\",\"path_prefix\":\"/\",\"backend_ids\":[\"${backend}\"],\"certificate_id\":\"${cert}\"${extra:+,$extra}}")
    id=$(json_field "$route" '.data.id // empty')
    [ -n "$id" ] || die "route ${host}: $route"
    echo "routes $id" >> "$CREATED_FILE"
}

# Repeat a request until it answers <status> (a reload or a certificate
# load is asynchronous), at most 15 s; prints the last answer.
wait_status() {
    local want="$1" i out
    shift
    for i in $(seq 1 30); do
        out=$("$@")
        if [ "$(json_field "$out" '.status // empty')" = "$want" ]; then
            printf '%s' "$out"
            return 0
        fi
        sleep 0.5
    done
    printf '%s' "$out"
    return 1
}

# The access-log rows of <host> for <client_ip>, polled until <status>
# shows, at most 10 s; prints the matching row.
wait_log_row() {
    local host="$1" ip="$2" status="$3" i row
    for i in $(seq 1 20); do
        row=$(api_get "/api/v1/logs?route=${host}&limit=200" \
            | jq -c --arg ip "$ip" --argjson st "$status" \
                '[.data.entries[] | select(.client_ip == $ip and .status == $st)] | last // empty')
        if [ -n "$row" ]; then
            printf '%s' "$row"
            return 0
        fi
        sleep 0.5
    done
    return 1
}

RUNNER_IP=$($CLIENT self-ip --host "$NODE_HOST")

# ---- 12.8 IV1 ----------------------------------------------------------

# Behind an L4 load balancer sending PROXY v2, an HTTPS route logs,
# rate-limits, GeoIP-filters and forwards X-Forwarded-For with the
# original client address.
scenario_iv1() {
    local geo=pp-geo.test rl=pp-rl.test out us kr echo xreal xff row_kr row_us codes other acc_before acc_after
    make_route "$geo" '"geoip":{"mode":"denylist","countries":["US"]}'
    make_route "$rl" '"rate_limit":{"capacity":2,"refill_per_sec":0,"scope":"per_ip"}'
    acc_before=$(metric_value lorica_proxy_protocol_accepted_total 'listener="https"' 'kind="v2"')
    settings_put "{\"proxy_protocol_https\":\"required\",\"proxy_protocol_trusted_cidrs\":[\"${RUNNER_IP}/32\"]}"

    kr=$(wait_status 200 https_request "$geo" 2 "$IP_KR" "$(dst_for "$IP_KR")" --path /echo) \
        || die "a v2 header carrying ${IP_KR} (KR) never got 200: $kr"
    us=$(https_request "$geo" 2 "$IP_US" "$(dst_for "$IP_US")")
    [ "$(json_field "$us" .status)" = 403 ] || die "a v2 header carrying ${IP_US} (US, denied) got: $us"

    echo=$(json_field "$kr" .body)
    xreal=$(json_field "$echo" '.received_headers["x-real-ip"] // empty')
    xff=$(json_field "$echo" '.received_headers["x-forwarded-for"] // empty')
    [ "$xreal" = "$IP_KR" ] || die "the backend got X-Real-IP '${xreal}', not the carried ${IP_KR}"
    [ "${xff##*, }" = "$IP_KR" ] || die "the backend's X-Forwarded-For '${xff}' does not end with the carried ${IP_KR}"

    row_kr=$(wait_log_row "$geo" "$IP_KR" 200) || die "no access-log row of ${geo} for ${IP_KR} with 200"
    row_us=$(wait_log_row "$geo" "$IP_US" 403) || die "no access-log row of ${geo} for ${IP_US} with 403"
    [ "$(json_field "$row_kr" .is_xff)" = false ] || die "the KR row is marked as an X-Forwarded-For address: $row_kr"

    # The warm-up address spends its own bucket only (per_ip scope).
    out=$(wait_status 200 https_request "$rl" 2 "$IP_RL_WARMUP") || die "route ${rl} never answered: $out"
    codes=""
    local i
    for i in 1 2 3; do
        codes="$codes $(json_field "$(https_request "$rl" 2 "$IP_RL_A")" .status)"
    done
    [ "$codes" = " 200 200 429" ] || die "three requests carrying ${IP_RL_A} on a 2-request bucket answered${codes}, not 200 200 429"
    other=$(json_field "$(https_request "$rl" 2 "$IP_RL_B")" .status)
    [ "$other" = 200 ] || die "${IP_RL_B} was limited (${other}) after ${IP_RL_A} spent its bucket"

    acc_after=$(metric_value lorica_proxy_protocol_accepted_total 'listener="https"' 'kind="v2"')
    [ "$acc_after" -gt "$acc_before" ] || die "lorica_proxy_protocol_accepted_total{listener=https,kind=v2} did not grow (${acc_before} -> ${acc_after})"

    verdict_pass "v2 from ${RUNNER_IP}: carried US ${IP_US} 403 and KR ${IP_KR} 200 by GeoIP; access log rows client_ip ${IP_KR} (200) and ${IP_US} (403), is_xff false; backend X-Real-IP ${xreal}, X-Forwarded-For '${xff}'; per-IP bucket of 2: ${IP_RL_A}${codes}, ${IP_RL_B} ${other}; accepted v2 ${acc_before} -> ${acc_after}"
}

# ---- 12.8 IV2 ----------------------------------------------------------

# A direct connection from outside the trusted CIDRs carrying a PROXY
# header is disconnected, and one carrying a forged X-Forwarded-For
# behind a trusted PROXY peer is logged with the PROXY address.
scenario_iv2() {
    local host="pp-xff-${PROFILE}.test" out echo xreal xff row plain v1 v2 ref_before ref_after i
    make_route "$host"

    # Trusted peer, forged X-Forwarded-For behind the header. The geoip
    # smoke trusts 0.0.0.0/0 in trusted_proxies, so only the no-stacking
    # rule keeps the forged address out.
    settings_put "{\"proxy_protocol_https\":\"required\",\"proxy_protocol_trusted_cidrs\":[\"${RUNNER_IP}/32\"]}"
    out=$(wait_status 200 https_request "$host" 2 "$IP_CARRIED" "$(dst_for "$IP_CARRIED")" \
        --path /echo --header "X-Forwarded-For: ${IP_FORGED}") \
        || die "a trusted v2 header with a forged X-Forwarded-For never got 200: $out"
    echo=$(json_field "$out" .body)
    xreal=$(json_field "$echo" '.received_headers["x-real-ip"] // empty')
    xff=$(json_field "$echo" '.received_headers["x-forwarded-for"] // empty')
    [ "$xreal" = "$IP_CARRIED" ] || die "X-Real-IP is '${xreal}', not the carried ${IP_CARRIED}"
    [ "$xff" = "${IP_FORGED}, ${IP_CARRIED}" ] || die "X-Forwarded-For is '${xff}', not the client's entry then the carried address"
    row=$(wait_log_row "$host" "$IP_CARRIED" 200) || die "no access-log row of ${host} with the carried ${IP_CARRIED}"
    [ "$(json_field "$row" .is_xff)" = false ] || die "the row read the forged X-Forwarded-For: $row"
    if api_get "/api/v1/logs?route=${host}&limit=200" | jq -e --arg ip "$IP_FORGED" '.data.entries[] | select(.client_ip == $ip)' >/dev/null; then
        die "an access-log row of ${host} carries the forged ${IP_FORGED}"
    fi

    # The runner leaves the trust list: it is now a direct client.
    ref_before=$(metric_value lorica_proxy_protocol_refused_total 'listener="https"' 'reason="untrusted_peer"')
    settings_put "{\"proxy_protocol_https\":\"required\",\"proxy_protocol_trusted_cidrs\":[\"${UNTRUSTED_CIDR}\"]}"
    plain=$(wait_status 200 https_request "$host" none) \
        || die "a plain request was not served once the runner left the trust list: $plain"
    v1=$(https_request "$host" 1 "$IP_CARRIED" "$(dst_for "$IP_CARRIED")")
    v2=$(https_request "$host" 2 "$IP_CARRIED" "$(dst_for "$IP_CARRIED")")
    [ "$(json_field "$v1" .outcome)" = disconnected ] || die "an untrusted v1 header was not disconnected: $v1"
    [ "$(json_field "$v2" .outcome)" = disconnected ] || die "an untrusted v2 header was not disconnected: $v2"
    plain=$(https_request "$host" none)
    [ "$(json_field "$plain" .status)" = 200 ] || die "a plain request after the refusals was not served: $plain"

    for i in $(seq 1 30); do
        ref_after=$(metric_value lorica_proxy_protocol_refused_total 'listener="https"' 'reason="untrusted_peer"')
        [ $((ref_after - ref_before)) -ge 2 ] && break
        sleep 0.5
    done
    [ $((ref_after - ref_before)) -eq 2 ] \
        || die "lorica_proxy_protocol_refused_total{listener=https,reason=untrusted_peer} moved ${ref_before} -> ${ref_after}, not by the 2 refusals"

    verdict_pass "trusted v2 carrying ${IP_CARRIED} with a forged X-Forwarded-For ${IP_FORGED}: logged as ${IP_CARRIED} (is_xff false), X-Real-IP ${xreal}, X-Forwarded-For '${xff}'; runner untrusted: v1 and v2 headers disconnected, untrusted_peer ${ref_before} -> ${ref_after}, plain requests 200"
}

# Never call run_scenario from a conditional context (`||`, `if`): the
# scenario's own `set -e` would be ignored. Errexit is off here instead.
set +e
FAILED=0
case "$PROFILE" in
    geoip)
        run_scenario 12.8-iv1-proxy-v2-https-real-client scenario_iv1
        [ $? -eq 0 ] || FAILED=1
        pp_cleanup
        run_scenario 12.8-iv2-untrusted-and-forged-xff scenario_iv2
        [ $? -eq 0 ] || FAILED=1
        ;;
    workers)
        run_scenario 12.8-iv2-untrusted-and-forged-xff scenario_iv2
        [ $? -eq 0 ] || FAILED=1
        ;;
    *)
        echo "run-proxy-protocol-smoke.sh: unknown profile ${PROFILE}" >&2
        exit 2
        ;;
esac
exit "$FAILED"
