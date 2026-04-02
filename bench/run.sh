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

# Login
SESSION=$(mktemp)
docker compose exec -T lorica bash -c '
    PW=$(cat /var/lib/lorica/admin-password 2>/dev/null || echo "")
    curl -sf -c /tmp/sess -H "Content-Type: application/json" \
        -d "{\"password\":\"$PW\"}" http://127.0.0.1:9443/api/v1/auth/login >/dev/null
    # Change password
    curl -sf -b /tmp/sess -X PUT -H "Content-Type: application/json" \
        -d "{\"current_password\":\"$PW\",\"new_password\":\"benchpass123\"}" \
        http://127.0.0.1:9443/api/v1/auth/password >/dev/null 2>&1 || true
    # Re-login with new password
    curl -sf -c /tmp/sess -H "Content-Type: application/json" \
        -d "{\"password\":\"benchpass123\"}" http://127.0.0.1:9443/api/v1/auth/login >/dev/null 2>&1 || true
    cat /tmp/sess
' > "$SESSION" 2>/dev/null

# Create backends and route inside the lorica container
docker compose exec -T lorica bash -c '
    API="http://127.0.0.1:9443"
    SESS="/tmp/sess"

    B1=$(curl -sf -b $SESS -X POST -H "Content-Type: application/json" \
        -d "{\"address\":\"backend1:80\",\"health_check_enabled\":false}" \
        $API/api/v1/backends)
    B1_ID=$(echo "$B1" | grep -o "\"id\":\"[^\"]*\"" | head -1 | cut -d\" -f4)

    B2=$(curl -sf -b $SESS -X POST -H "Content-Type: application/json" \
        -d "{\"address\":\"backend2:80\",\"health_check_enabled\":false}" \
        $API/api/v1/backends)
    B2_ID=$(echo "$B2" | grep -o "\"id\":\"[^\"]*\"" | head -1 | cut -d\" -f4)

    curl -sf -b $SESS -X POST -H "Content-Type: application/json" \
        -d "{\"hostname\":\"bench.local\",\"path_prefix\":\"/\",\"backend_ids\":[\"$B1_ID\",\"$B2_ID\"],\"enabled\":true,\"waf_enabled\":'$WAF_ENABLED',\"cache_enabled\":'$CACHE_ENABLED'}" \
        $API/api/v1/routes >/dev/null

    echo "Route created: backends=$B1_ID,$B2_ID waf='$WAF_ENABLED' cache='$CACHE_ENABLED'"
'
rm -f "$SESSION"
sleep 2

# --- Install oha in runner ---
echo "[4/6] Installing oha..."
docker compose up -d runner
docker compose exec -T runner sh -c '
    apk add --no-cache curl jq >/dev/null 2>&1
    curl -sL https://github.com/hatoo/oha/releases/latest/download/oha-linux-amd64 -o /usr/local/bin/oha
    chmod +x /usr/local/bin/oha
    oha --version
' 2>&1 | tail -1

# --- Run benchmark ---
echo "[5/6] Running benchmark (${DURATION}s, ${CONNECTIONS} connections)..."
echo ""

docker compose exec -T runner oha \
    -z "${DURATION}s" \
    -c "$CONNECTIONS" \
    -H "Host: bench.local" \
    --json \
    "http://lorica:8080/" > "$RESULT_JSON" 2>/dev/null

# --- Parse results ---
echo "[6/6] Results:"
echo ""

RPS=$(jq -r '.summary.requestsPerSec' "$RESULT_JSON")
TOTAL=$(jq -r '.summary.total' "$RESULT_JSON")
FASTEST=$(jq -r '.summary.fastest' "$RESULT_JSON")
SLOWEST=$(jq -r '.summary.slowest' "$RESULT_JSON")
AVG=$(jq -r '.summary.average' "$RESULT_JSON")
P50=$(jq -r '.latencyPercentiles[] | select(.percentile == 50) | .latency' "$RESULT_JSON" 2>/dev/null || echo "N/A")
P95=$(jq -r '.latencyPercentiles[] | select(.percentile == 95) | .latency' "$RESULT_JSON" 2>/dev/null || echo "N/A")
P99=$(jq -r '.latencyPercentiles[] | select(.percentile == 99) | .latency' "$RESULT_JSON" 2>/dev/null || echo "N/A")
STATUS_2XX=$(jq -r '.statusCodeDistribution."200" // 0' "$RESULT_JSON")
STATUS_OTHER=$(jq -r '[.statusCodeDistribution | to_entries[] | select(.key != "200") | .value] | add // 0' "$RESULT_JSON")

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
  Total:         ${TOTAL} requests
  Avg latency:   ${AVG}
  p50:           ${P50}
  p95:           ${P95}
  p99:           ${P99}
  Fastest:       ${FASTEST}
  Slowest:       ${SLOWEST}
  2xx:           ${STATUS_2XX}
  Errors:        ${STATUS_OTHER}
============================================
REPORT

cat "$RESULT_TXT"

# Symlink latest
ln -sf "bench-${TIMESTAMP}.txt" results/LATEST.txt
ln -sf "bench-${TIMESTAMP}.json" results/LATEST.json

# --- Cleanup ---
docker compose down -v 2>/dev/null

echo ""
echo "Full results: $RESULT_JSON"
echo "Summary:      $RESULT_TXT"
