#!/usr/bin/env bash
# =============================================================================
# Lorica Reproducible Benchmark
#
# Measures proxy throughput and latency using oha (HTTP load generator).
# Runs entirely in Docker - no host dependencies beyond docker compose.
#
# Usage:
#   ./run.sh [--duration 30] [--connections 100] [--workers 0] [--build]
#
# Produces:
#   results/bench-<timestamp>.json   (oha JSON output)
#   results/bench-<timestamp>.txt    (human-readable summary)
#   results/LATEST.txt               (symlink to latest summary)
# =============================================================================

set -euo pipefail
cd "$(dirname "$0")"

# --- Defaults ---
DURATION=30
CONNECTIONS=100
WORKERS=0
BUILD_FLAG=""
WAF_ENABLED=false
CACHE_ENABLED=false

# --- Parse args ---
while [[ $# -gt 0 ]]; do
    case "$1" in
        --duration)     DURATION="$2"; shift 2 ;;
        --connections)  CONNECTIONS="$2"; shift 2 ;;
        --workers)      WORKERS="$2"; shift 2 ;;
        --waf)          WAF_ENABLED=true; shift ;;
        --cache)        CACHE_ENABLED=true; shift ;;
        --build)        BUILD_FLAG="--build"; shift ;;
        *) echo "Unknown: $1"; exit 1 ;;
    esac
done

TIMESTAMP=$(date +%Y%m%d-%H%M%S)
RESULT_JSON="results/bench-${TIMESTAMP}.json"
RESULT_TXT="results/bench-${TIMESTAMP}.txt"
mkdir -p results

echo "============================================"
echo "  Lorica Benchmark"
echo "============================================"
echo "  Duration:    ${DURATION}s"
echo "  Connections: ${CONNECTIONS}"
echo "  Workers:     ${WORKERS} (0 = single-process)"
echo "  WAF:         ${WAF_ENABLED}"
echo "  Cache:       ${CACHE_ENABLED}"
echo "============================================"
echo ""

# --- Start infrastructure ---
echo "[1/6] Starting containers..."

if [ "$WORKERS" -gt 0 ]; then
    LORICA_CMD="--data-dir=/var/lib/lorica --http-port=8080 --https-port=8443 --management-port=9443 --log-level=warn --workers=${WORKERS}"
    docker compose down -v 2>/dev/null || true
    LORICA_COMMAND="$LORICA_CMD" docker compose up $BUILD_FLAG -d lorica backend1 backend2
else
    docker compose down -v 2>/dev/null || true
    docker compose up $BUILD_FLAG -d lorica backend1 backend2
fi

# --- Wait for Lorica ---
echo "[2/6] Waiting for Lorica API..."
for i in $(seq 1 60); do
    if docker compose exec -T lorica curl -sf http://127.0.0.1:9443/ >/dev/null 2>&1; then
        echo "  Lorica ready."
        break
    fi
    if [ "$i" = "60" ]; then
        echo "  ERROR: Lorica did not start"
        docker compose logs lorica | tail -20
        docker compose down -v
        exit 1
    fi
    sleep 2
done

# --- Configure route ---
echo "[3/6] Configuring benchmark route..."

# Extract admin password from Lorica logs
ADMIN_PW=$(docker compose logs lorica 2>&1 | grep -o "Initial admin password: .*" | head -1 | sed "s/Initial admin password: //")
if [ -z "$ADMIN_PW" ]; then
    echo "  ERROR: could not extract admin password from logs"
    docker compose down -v
    exit 1
fi
echo "  Admin password extracted"

# Setup route inside the lorica container (all-in-one to avoid session issues)
docker compose exec -T -e ADMIN_PW="$ADMIN_PW" -e WAF_ENABLED="$WAF_ENABLED" -e CACHE_ENABLED="$CACHE_ENABLED" lorica bash -c '
    API="http://127.0.0.1:9443"
    extract_id() { sed -n "s/.*\"id\":\"\([^\"]*\)\".*/\1/p" | head -1; }
    PW="$ADMIN_PW"

    # Login
    curl -sf -c /tmp/sess -H "Content-Type: application/json" \
        -d "{\"username\":\"admin\",\"password\":\"$PW\"}" \
        $API/api/v1/auth/login >/dev/null

    # Change password (required on first login)
    curl -sf -b /tmp/sess -X PUT -H "Content-Type: application/json" \
        -d "{\"current_password\":\"$PW\",\"new_password\":\"benchpass1!\"}" \
        $API/api/v1/auth/password >/dev/null 2>&1 || true

    # Re-login
    curl -sf -c /tmp/sess -H "Content-Type: application/json" \
        -d "{\"username\":\"admin\",\"password\":\"benchpass1!\"}" \
        $API/api/v1/auth/login >/dev/null 2>&1 || true

    # Create backends
    B1_ID=$(curl -sf -b /tmp/sess -X POST -H "Content-Type: application/json" \
        -d "{\"address\":\"backend1:80\",\"health_check_enabled\":false}" \
        $API/api/v1/backends | extract_id)

    B2_ID=$(curl -sf -b /tmp/sess -X POST -H "Content-Type: application/json" \
        -d "{\"address\":\"backend2:80\",\"health_check_enabled\":false}" \
        $API/api/v1/backends | extract_id)

    echo "  Backends: $B1_ID $B2_ID"

    # Create route
    curl -sf -b /tmp/sess -X POST -H "Content-Type: application/json" \
        -d "{\"hostname\":\"bench.local\",\"path_prefix\":\"/\",\"backend_ids\":[\"$B1_ID\",\"$B2_ID\"],\"enabled\":true,\"waf_enabled\":$WAF_ENABLED,\"cache_enabled\":$CACHE_ENABLED}" \
        $API/api/v1/routes >/dev/null

    echo "  Route created (waf=$WAF_ENABLED cache=$CACHE_ENABLED)"
'
sleep 2

# --- Install oha in runner ---
echo "[4/6] Installing oha..."
docker compose up -d runner
docker compose exec -T runner sh -c '
    apk add --no-cache curl util-linux >/dev/null 2>&1
    curl -sL https://github.com/hatoo/oha/releases/latest/download/oha-linux-amd64 -o /usr/local/bin/oha
    chmod +x /usr/local/bin/oha
    oha --version
' 2>&1 | tail -1

# --- Run benchmark ---
echo "[5/6] Running benchmark (${DURATION}s, ${CONNECTIONS} connections)..."
echo ""

# Run oha (use script to allocate PTY - oha needs a terminal for output)
set +e
docker compose exec -T runner sh -c \
    "script -qc \"oha --no-tui -z ${DURATION}s -c ${CONNECTIONS} -H 'Host: bench.local' http://lorica:8080/\" /dev/null 2>/dev/null" \
    | sed 's/\x1b\[[0-9;]*m//g' > results/oha-raw.txt
set -e
sync
OHA_SIZE=$(wc -c < results/oha-raw.txt 2>/dev/null || echo "0")
echo "  oha output: ${OHA_SIZE} bytes"
OHA_OUTPUT=$(cat results/oha-raw.txt 2>/dev/null || echo "")

# --- Parse results ---
echo "[6/6] Results:"
echo ""

# Extract values from oha text output (|| true to avoid pipefail on missing patterns)
extract() { echo "$OHA_OUTPUT" | grep "$1" | head -1 | awk "{print \$$2}" || true; }
RPS=$(extract "Requests/sec" 2)
TOTAL_TIME=$(extract "Total:" 2)
AVG=$(extract "Average:" 2)
FASTEST=$(extract "Fastest:" 2)
SLOWEST=$(extract "Slowest:" 2)
SUCCESS=$(extract "Success rate" 3)
P50=$(extract "50.00%" 3)
P95=$(extract "95.00%" 3)
P99=$(extract "99.00%" 3)
STATUS_2XX=$(echo "$OHA_OUTPUT" | grep "200 " | head -1 | awk '{print $2}' || true)

cat > "$RESULT_TXT" << REPORT
============================================
  Lorica Benchmark Results
============================================
  Date:          $(date -Iseconds)
  Duration:      ${DURATION}s
  Connections:   ${CONNECTIONS}
  Workers:       ${WORKERS}
  WAF:           ${WAF_ENABLED}
  Cache:         ${CACHE_ENABLED}
--------------------------------------------
  Throughput:    ${RPS} req/s
  Success rate:  ${SUCCESS}
  Avg latency:   ${AVG}
  p50:           ${P50}
  p95:           ${P95}
  p99:           ${P99}
  Fastest:       ${FASTEST}
  Slowest:       ${SLOWEST}
  2xx responses: ${STATUS_2XX}
============================================
REPORT

cat "$RESULT_TXT"

# Save full oha output
echo "$OHA_OUTPUT" > "$RESULT_JSON"

# Symlink latest
ln -sf "bench-${TIMESTAMP}.txt" results/LATEST.txt
ln -sf "bench-${TIMESTAMP}.json" results/LATEST.json

# --- Cleanup ---
docker compose down -v 2>/dev/null

echo ""
echo "Full output: $RESULT_JSON"
echo "Summary:     $RESULT_TXT"
