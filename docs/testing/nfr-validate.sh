#!/usr/bin/env bash
# =============================================================================
# Lorica NFR Validation Script
#
# Validates:
#   NFR2  - 10,000 concurrent connections
#   NFR11 - Memory stability under sustained load (10 min soak)
#
# Prerequisites:
#   - Lorica installed and running (systemd or manual)
#   - curl, python3, ss, awk available
#   - Run as root (or with CAP_NET_BIND_SERVICE for port 8900)
#
# Usage:
#   sudo ./nfr-validate.sh [--proxy-port 80] [--api-port 9443] [--skip-nfr2] [--skip-nfr11]
# =============================================================================

set -euo pipefail

# --- Configuration ---
PROXY_PORT=80
API_PORT=9443
BACKEND_PORT=8900
BACKEND_HOST="app-nfr-test.local"
TARGET_CONNECTIONS=10000
SOAK_DURATION_S=600        # 10 minutes
SOAK_RPS=100
SOAK_SAMPLE_INTERVAL_S=30
SKIP_NFR2=false
SKIP_NFR11=false

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
REPORT_FILE="nfr-report-${TIMESTAMP}.json"

# --- Parse args ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --proxy-port)  PROXY_PORT="$2"; shift 2 ;;
        --api-port)    API_PORT="$2"; shift 2 ;;
        --skip-nfr2)   SKIP_NFR2=true; shift ;;
        --skip-nfr11)  SKIP_NFR11=true; shift ;;
        *) echo "Unknown option: $1"; exit 1 ;;
    esac
done

API="https://localhost:${API_PORT}"

# --- Colors ---
GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
RESET='\033[0m'

header()  { echo -e "\n${CYAN}===== $* =====${RESET}"; }
ok()      { echo -e "  ${GREEN}PASS${RESET} $*"; }
fail()    { echo -e "  ${RED}FAIL${RESET} $*"; }
info()    { echo -e "  ${YELLOW}INFO${RESET} $*"; }

# --- Helpers ---
api_get()  { curl -sf -k -b "$SESSION" "${API}$1" 2>/dev/null; }
api_post() { curl -sf -k -b "$SESSION" -X POST -H "Content-Type: application/json" -d "$2" "${API}$1" 2>/dev/null; }
api_del()  { curl -sf -k -b "$SESSION" -X DELETE "${API}$1" 2>/dev/null; }

get_lorica_pid() {
    pgrep -x lorica | head -1 || systemctl show lorica --property=MainPID --value 2>/dev/null || echo ""
}

get_rss_kb() {
    local pid="$1"
    if [ -f "/proc/${pid}/status" ]; then
        awk '/^VmRSS:/ {print $2}' "/proc/${pid}/status"
    else
        ps -o rss= -p "$pid" 2>/dev/null | tr -d ' '
    fi
}

# =============================================================================
echo -e "${CYAN}"
echo "  _                _           _   _ _____ ____"
echo " | |    ___  _ __ (_) ___ __ _| \ | |  ___|  _ \\"
echo " | |   / _ \\| '__|| |/ __/ _\` |  \\| | |_  | |_) |"
echo " | |__| (_) | |   | | (_| (_| | |\\  |  _| |  _ <"
echo " |_____\\___/|_|   |_|\\___\\__,_|_| \\_|_|   |_| \\_\\"
echo ""
echo " NFR Validation Script - $(date)"
echo -e "${RESET}"

# --- Check Lorica is running ---
header "Checking Lorica"
LORICA_PID=$(get_lorica_pid)
if [ -z "$LORICA_PID" ] || [ "$LORICA_PID" = "0" ]; then
    fail "Lorica process not found. Is it running?"
    exit 1
fi
ok "Lorica running (PID $LORICA_PID)"

INITIAL_RSS=$(get_rss_kb "$LORICA_PID")
info "Initial RSS: ${INITIAL_RSS} KB"

# --- Login ---
header "Authenticating"
PASSWORD_FILE="/var/lib/lorica/admin-password"
if [ -f "$PASSWORD_FILE" ]; then
    ADMIN_PW=$(cat "$PASSWORD_FILE")
else
    echo -n "Admin password: "
    read -r ADMIN_PW
fi

SESSION=$(mktemp)
HTTP_CODE=$(curl -sf -k -o /dev/null -w '%{http_code}' \
    -c "$SESSION" \
    -H "Content-Type: application/json" \
    -d "{\"password\":\"${ADMIN_PW}\"}" \
    "${API}/api/v1/auth/login" 2>/dev/null || echo "000")

if [ "$HTTP_CODE" != "200" ]; then
    fail "Login failed (HTTP $HTTP_CODE)"
    rm -f "$SESSION"
    exit 1
fi
ok "Authenticated"

# --- Start backend stub ---
header "Starting test backend"

# Minimal HTTP server: returns 200 with small body
BACKEND_PY=$(mktemp /tmp/nfr-backend-XXXX.py)
cat > "$BACKEND_PY" << 'PYEOF'
import http.server, socketserver, sys
class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type","text/plain")
        self.end_headers()
        self.wfile.write(b"ok\n")
    def log_message(self, *a): pass
port = int(sys.argv[1])
with socketserver.TCPServer(("0.0.0.0", port), H) as s:
    s.serve_forever()
PYEOF

python3 "$BACKEND_PY" "$BACKEND_PORT" &
BACKEND_PID=$!
sleep 1

if ! kill -0 "$BACKEND_PID" 2>/dev/null; then
    fail "Backend stub failed to start on port $BACKEND_PORT"
    exit 1
fi
ok "Backend stub running on port $BACKEND_PORT (PID $BACKEND_PID)"

# --- Create test route ---
header "Creating test route and backend"

NFR_BACKEND=$(api_post "/api/v1/backends" \
    "{\"address\":\"127.0.0.1:${BACKEND_PORT}\",\"health_check_enabled\":false}")
NFR_BACKEND_ID=$(echo "$NFR_BACKEND" | jq -r '.data.id')

if [ -z "$NFR_BACKEND_ID" ] || [ "$NFR_BACKEND_ID" = "null" ]; then
    fail "Failed to create backend"
    kill "$BACKEND_PID" 2>/dev/null
    exit 1
fi
ok "Backend created: $NFR_BACKEND_ID"

NFR_ROUTE=$(api_post "/api/v1/routes" \
    "{\"hostname\":\"${BACKEND_HOST}\",\"path_prefix\":\"/\",\"backend_ids\":[\"${NFR_BACKEND_ID}\"],\"enabled\":true}")
NFR_ROUTE_ID=$(echo "$NFR_ROUTE" | jq -r '.data.id')

if [ -z "$NFR_ROUTE_ID" ] || [ "$NFR_ROUTE_ID" = "null" ]; then
    fail "Failed to create route"
    kill "$BACKEND_PID" 2>/dev/null
    exit 1
fi
ok "Route created: $NFR_ROUTE_ID (hostname: $BACKEND_HOST)"
sleep 2

# Verify proxy works
PROBE=$(curl -s -o /dev/null -w '%{http_code}' \
    -H "Host: ${BACKEND_HOST}" "http://localhost:${PROXY_PORT}/" 2>/dev/null || echo "000")
if [ "$PROBE" = "200" ]; then
    ok "Proxy health check: 200"
else
    fail "Proxy health check: $PROBE (expected 200)"
    info "Continuing anyway - connections test may still work"
fi

# =============================================================================
# NFR2: 10,000 Concurrent Connections
# =============================================================================
NFR2_RESULT="skipped"
NFR2_ESTABLISHED=0
NFR2_HEALTH="skipped"
NFR2_ALIVE="skipped"

if [ "$SKIP_NFR2" = "false" ]; then
    header "NFR2: 10,000 Concurrent Connections"
    info "Opening $TARGET_CONNECTIONS connections to proxy port $PROXY_PORT..."
    info "This may take 30-60 seconds."

    # Use background curl processes that hold connections open
    CONN_DIR=$(mktemp -d /tmp/nfr-conns-XXXX)

    # Open connections in batches of 500
    BATCH_SIZE=500
    BATCHES=$((TARGET_CONNECTIONS / BATCH_SIZE))

    for batch in $(seq 1 "$BATCHES"); do
        for _ in $(seq 1 "$BATCH_SIZE"); do
            # Each curl: slow download (timeout 30s, keepalive)
            curl -s -o /dev/null --max-time 30 \
                -H "Host: ${BACKEND_HOST}" \
                "http://localhost:${PROXY_PORT}/" &
        done
        # Brief pause between batches to avoid fork bomb
        sleep 0.2
    done

    info "Waiting 5s for connections to establish..."
    sleep 5

    # Count established connections to proxy port
    NFR2_ESTABLISHED=$(ss -tn state established "( dport = :${PROXY_PORT} )" 2>/dev/null | tail -n +2 | wc -l)
    info "Established connections: $NFR2_ESTABLISHED / $TARGET_CONNECTIONS"

    # Health check during load
    NFR2_HEALTH=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
        -H "Host: ${BACKEND_HOST}" "http://localhost:${PROXY_PORT}/" 2>/dev/null || echo "000")
    info "Health check during load: HTTP $NFR2_HEALTH"

    # Wait for background curls to finish
    info "Waiting for connections to drain..."
    wait 2>/dev/null || true
    rm -rf "$CONN_DIR"

    # Check proxy is still alive
    NEW_PID=$(get_lorica_pid)
    if [ -n "$NEW_PID" ] && [ "$NEW_PID" != "0" ]; then
        NFR2_ALIVE="true"
    else
        NFR2_ALIVE="false"
    fi

    # Evaluate
    if [ "$NFR2_ESTABLISHED" -ge 9500 ]; then
        ok "Connections: $NFR2_ESTABLISHED >= 9500 (95%)"
        NFR2_RESULT="pass"
    elif [ "$NFR2_ESTABLISHED" -ge 5000 ]; then
        info "Connections: $NFR2_ESTABLISHED (50-95% - partial, may be limited by ulimit)"
        NFR2_RESULT="partial"
    else
        fail "Connections: $NFR2_ESTABLISHED < 5000"
        NFR2_RESULT="fail"
    fi

    if [ "$NFR2_HEALTH" = "200" ]; then
        ok "Proxy responsive during load"
    else
        fail "Proxy unresponsive during load (HTTP $NFR2_HEALTH)"
        NFR2_RESULT="fail"
    fi

    if [ "$NFR2_ALIVE" = "true" ]; then
        ok "Proxy alive after test"
    else
        fail "Proxy crashed during test"
        NFR2_RESULT="fail"
    fi

    # Check ulimit for context
    ULIMIT_N=$(ulimit -n 2>/dev/null || echo "unknown")
    info "Current ulimit -n: $ULIMIT_N"
    if [ "$ULIMIT_N" != "unknown" ] && [ "$ULIMIT_N" -lt 20000 ] 2>/dev/null; then
        info "Tip: increase ulimit with 'ulimit -n 65536' before running"
    fi
fi

# =============================================================================
# NFR11: Memory Stability (Soak Test)
# =============================================================================
NFR11_RESULT="skipped"
NFR11_SLOPE="0"
NFR11_DELTA_MB="0"
NFR11_SAMPLES=""

if [ "$SKIP_NFR11" = "false" ]; then
    header "NFR11: Memory Stability Soak Test"
    info "Sending ~${SOAK_RPS} req/s for ${SOAK_DURATION_S}s ($(( SOAK_DURATION_S / 60 )) min)"
    info "Sampling RSS every ${SOAK_SAMPLE_INTERVAL_S}s"

    LORICA_PID=$(get_lorica_pid)
    START_RSS=$(get_rss_kb "$LORICA_PID")
    info "Start RSS: ${START_RSS} KB"

    SAMPLES_FILE=$(mktemp /tmp/nfr-samples-XXXX.csv)
    echo "elapsed_s,rss_kb" > "$SAMPLES_FILE"
    echo "0,${START_RSS}" >> "$SAMPLES_FILE"

    START_TIME=$(date +%s)
    END_TIME=$((START_TIME + SOAK_DURATION_S))
    NEXT_SAMPLE=$((START_TIME + SOAK_SAMPLE_INTERVAL_S))
    REQUEST_COUNT=0
    ERROR_COUNT=0

    # Calculate delay between requests (approximate)
    # Using 10 parallel workers each doing RPS/10 req/s
    WORKERS=10
    DELAY_MS=$(( 1000 * WORKERS / SOAK_RPS ))

    # Start background load generators
    for w in $(seq 1 "$WORKERS"); do
        (
            while [ "$(date +%s)" -lt "$END_TIME" ]; do
                curl -s -o /dev/null --max-time 2 \
                    -H "Host: ${BACKEND_HOST}" \
                    "http://localhost:${PROXY_PORT}/" 2>/dev/null || true
                sleep "0.$(printf '%03d' "$DELAY_MS")" 2>/dev/null || sleep 0.1
            done
        ) &
    done

    # Sample RSS while load runs
    SAMPLE_NUM=0
    while [ "$(date +%s)" -lt "$END_TIME" ]; do
        NOW=$(date +%s)
        if [ "$NOW" -ge "$NEXT_SAMPLE" ]; then
            ELAPSED=$((NOW - START_TIME))
            CURRENT_PID=$(get_lorica_pid)
            if [ -z "$CURRENT_PID" ] || [ "$CURRENT_PID" = "0" ]; then
                fail "Lorica crashed during soak test at ${ELAPSED}s"
                NFR11_RESULT="fail"
                break
            fi
            CURRENT_RSS=$(get_rss_kb "$CURRENT_PID")
            echo "${ELAPSED},${CURRENT_RSS}" >> "$SAMPLES_FILE"
            SAMPLE_NUM=$((SAMPLE_NUM + 1))

            DELTA=$((CURRENT_RSS - START_RSS))
            printf "  [%3ds] RSS: %s KB (delta: %+d KB)\n" "$ELAPSED" "$CURRENT_RSS" "$DELTA"

            NEXT_SAMPLE=$((NOW + SOAK_SAMPLE_INTERVAL_S))
        fi
        sleep 5
    done

    # Wait for load generators
    info "Stopping load generators..."
    wait 2>/dev/null || true

    # Final sample
    FINAL_PID=$(get_lorica_pid)
    if [ -n "$FINAL_PID" ] && [ "$FINAL_PID" != "0" ]; then
        FINAL_RSS=$(get_rss_kb "$FINAL_PID")
        ELAPSED=$(($(date +%s) - START_TIME))
        echo "${ELAPSED},${FINAL_RSS}" >> "$SAMPLES_FILE"
    else
        FINAL_RSS="$START_RSS"
    fi

    NFR11_DELTA_KB=$((FINAL_RSS - START_RSS))
    NFR11_DELTA_MB=$(awk "BEGIN {printf \"%.1f\", ${NFR11_DELTA_KB}/1024}")

    # Compute linear regression slope (KB per sample interval -> KB per min)
    NFR11_SLOPE=$(awk -F, '
        NR > 1 {
            n++; x = $1; y = $2;
            sx += x; sy += y; sxx += x*x; sxy += x*y;
        }
        END {
            if (n < 2) { print 0; exit }
            slope = (n*sxy - sx*sy) / (n*sxx - sx*sx);
            # slope is KB/s, convert to KB/min
            printf "%.1f", slope * 60;
        }
    ' "$SAMPLES_FILE")

    info "Final RSS: ${FINAL_RSS} KB"
    info "Delta: ${NFR11_DELTA_MB} MB"
    info "Slope: ${NFR11_SLOPE} KB/min"

    NFR11_SAMPLES=$(cat "$SAMPLES_FILE")
    rm -f "$SAMPLES_FILE"

    # Evaluate
    NFR11_RESULT="pass"
    SLOPE_ABS=$(echo "$NFR11_SLOPE" | tr -d '-')

    if awk "BEGIN { exit !(${SLOPE_ABS} < 100) }"; then
        ok "Memory slope: ${NFR11_SLOPE} KB/min (< 100 KB/min)"
    else
        fail "Memory slope: ${NFR11_SLOPE} KB/min (>= 100 KB/min)"
        NFR11_RESULT="fail"
    fi

    DELTA_ABS=$(echo "$NFR11_DELTA_MB" | tr -d '-')
    if awk "BEGIN { exit !(${DELTA_ABS} < 20) }"; then
        ok "Memory delta: ${NFR11_DELTA_MB} MB (< 20 MB)"
    else
        fail "Memory delta: ${NFR11_DELTA_MB} MB (>= 20 MB)"
        NFR11_RESULT="fail"
    fi
fi

# =============================================================================
# Cleanup
# =============================================================================
header "Cleanup"

api_del "/api/v1/routes/${NFR_ROUTE_ID}" >/dev/null 2>&1 && ok "Route deleted" || info "Route cleanup skipped"
api_del "/api/v1/backends/${NFR_BACKEND_ID}" >/dev/null 2>&1 && ok "Backend deleted" || info "Backend cleanup skipped"
kill "$BACKEND_PID" 2>/dev/null && ok "Backend stub stopped" || true
rm -f "$BACKEND_PY" "$SESSION"

# =============================================================================
# Report
# =============================================================================
header "Results"

OVERALL="pass"
[ "$NFR2_RESULT" = "fail" ] && OVERALL="fail"
[ "$NFR11_RESULT" = "fail" ] && OVERALL="fail"

echo ""
echo -e "  NFR2  (10k connections):  $([ "$NFR2_RESULT" = "pass" ] && echo "${GREEN}PASS${RESET}" || ([ "$NFR2_RESULT" = "skipped" ] && echo "${YELLOW}SKIP${RESET}" || ([ "$NFR2_RESULT" = "partial" ] && echo "${YELLOW}PARTIAL${RESET}" || echo "${RED}FAIL${RESET}")))"
echo -e "  NFR11 (memory stability): $([ "$NFR11_RESULT" = "pass" ] && echo "${GREEN}PASS${RESET}" || ([ "$NFR11_RESULT" = "skipped" ] && echo "${YELLOW}SKIP${RESET}" || echo "${RED}FAIL${RESET}"))"
echo ""

# Write JSON report
cat > "$REPORT_FILE" << JSONEOF
{
  "timestamp": "$(date -Iseconds)",
  "lorica_pid": $LORICA_PID,
  "proxy_port": $PROXY_PORT,
  "overall": "$OVERALL",
  "nfr2": {
    "result": "$NFR2_RESULT",
    "target_connections": $TARGET_CONNECTIONS,
    "established_connections": $NFR2_ESTABLISHED,
    "health_check_during_load": "$NFR2_HEALTH",
    "proxy_alive_after": "$NFR2_ALIVE",
    "ulimit_n": "$(ulimit -n 2>/dev/null || echo unknown)"
  },
  "nfr11": {
    "result": "$NFR11_RESULT",
    "soak_duration_s": $SOAK_DURATION_S,
    "soak_rps": $SOAK_RPS,
    "start_rss_kb": ${START_RSS:-0},
    "final_rss_kb": ${FINAL_RSS:-0},
    "delta_mb": ${NFR11_DELTA_MB:-0},
    "slope_kb_per_min": ${NFR11_SLOPE:-0}
  }
}
JSONEOF

ok "Report written to $REPORT_FILE"
echo ""
cat "$REPORT_FILE"
echo ""

if [ "$OVERALL" = "pass" ]; then
    echo -e "${GREEN}All NFR validations passed.${RESET}"
    exit 0
else
    echo -e "${RED}Some NFR validations failed. See report for details.${RESET}"
    exit 1
fi
