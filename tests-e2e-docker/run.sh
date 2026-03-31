#!/usr/bin/env bash
# Run the Lorica E2E test suite with Docker Compose.
# Usage: ./run.sh [--build] [--keep] [--skip-workers]
#   --build         Force rebuild all images
#   --keep          Don't tear down containers after tests
#   --skip-workers  Skip worker isolation tests (faster)

set -euo pipefail
cd "$(dirname "$0")"

BUILD_FLAG=""
KEEP=false
SKIP_WORKERS=false

for arg in "$@"; do
    case "$arg" in
        --build)         BUILD_FLAG="--build" ;;
        --keep)          KEEP=true ;;
        --skip-workers)  SKIP_WORKERS=true ;;
    esac
done

EXIT_CODE=0

# ---- Phase 1: Single-process tests ----
echo "=== Lorica E2E Tests (single-process) ==="
echo ""

docker compose up $BUILD_FLAG -d backend1 backend2 lorica

echo "Waiting for Lorica to initialize..."
for i in $(seq 1 60); do
    if docker compose exec -T lorica curl -sf http://127.0.0.1:19443/ >/dev/null 2>&1; then
        echo "Lorica is ready."
        break
    fi
    if [ "$i" = "60" ]; then
        echo "ERROR: Lorica did not start within 120s"
        docker compose logs lorica | tail -20
        docker compose down -v
        exit 1
    fi
    sleep 2
done

docker compose run --rm test-runner || EXIT_CODE=$?

# ---- Phase 2: Worker isolation tests ----
if [ "$SKIP_WORKERS" = false ] && [ "$EXIT_CODE" = "0" ]; then
    echo ""
    echo "=== Lorica E2E Tests (worker isolation) ==="
    echo ""

    docker compose up $BUILD_FLAG -d lorica-workers

    echo "Waiting for Lorica workers to initialize..."
    for i in $(seq 1 60); do
        if docker compose exec -T lorica-workers curl -sf http://127.0.0.1:19443/ >/dev/null 2>&1; then
            echo "Lorica workers instance is ready."
            break
        fi
        if [ "$i" = "60" ]; then
            echo "ERROR: Lorica workers did not start within 120s"
            docker compose logs lorica-workers | tail -20
            break
        fi
        sleep 2
    done

    docker compose run --rm test-runner-workers || EXIT_CODE=$?
fi

# Cleanup unless --keep
if [ "$KEEP" = false ]; then
    docker compose down -v
fi

if [ "$EXIT_CODE" = "0" ]; then
    echo ""
    echo "=== ALL E2E TESTS PASSED ==="
fi

exit $EXIT_CODE
