#!/usr/bin/env bash
# Run the Lorica E2E test suite with Docker Compose.
# Usage: ./run.sh [--build] [--keep] [--skip-workers] [--skip-cert-export]
#   --build             Force rebuild all images
#   --keep              Don't tear down containers after tests
#   --skip-workers      Skip worker isolation tests (faster)
#   --skip-cert-export  Skip the v1.4.1 cert-export profile (faster)

set -euo pipefail
cd "$(dirname "$0")"

BUILD_FLAG=""
KEEP=false
SKIP_WORKERS=false
SKIP_CERT_EXPORT=false

for arg in "$@"; do
    case "$arg" in
        --build)             BUILD_FLAG="--build" ;;
        --keep)              KEEP=true ;;
        --skip-workers)      SKIP_WORKERS=true ;;
        --skip-cert-export)  SKIP_CERT_EXPORT=true ;;
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

# ---- Phase 3: Cert export profile ----
# Profile is opt-out via --skip-cert-export (default is ON) so the
# main suite covers the v1.4.1 filesystem export path end-to-end.
if [ "$SKIP_CERT_EXPORT" = false ] && [ "$EXIT_CODE" = "0" ]; then
    echo ""
    echo "=== Lorica E2E Tests (cert export profile) ==="
    echo ""

    docker compose --profile cert-export up $BUILD_FLAG -d lorica-cert-export

    echo "Waiting for Lorica (cert-export) to initialize..."
    for i in $(seq 1 60); do
        if docker compose exec -T lorica-cert-export curl -sf http://127.0.0.1:19443/ >/dev/null 2>&1; then
            echo "Lorica (cert-export) is ready."
            break
        fi
        if [ "$i" = "60" ]; then
            echo "ERROR: Lorica (cert-export) did not start within 120s"
            docker compose logs lorica-cert-export | tail -20
            break
        fi
        sleep 2
    done

    docker compose --profile cert-export run --rm cert-export-smoke || EXIT_CODE=$?
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
