#!/usr/bin/env bash
# Run the Lorica E2E test suite with Docker Compose.
# Usage: ./run.sh [--build] [--keep]
#   --build  Force rebuild all images
#   --keep   Don't tear down containers after tests

set -euo pipefail
cd "$(dirname "$0")"

BUILD_FLAG=""
KEEP=false

for arg in "$@"; do
    case "$arg" in
        --build) BUILD_FLAG="--build" ;;
        --keep)  KEEP=true ;;
    esac
done

echo "=== Lorica E2E Tests ==="
echo ""

# Build and start services
docker compose up $BUILD_FLAG -d backend1 backend2 lorica

# Poll until Lorica API is reachable (dashboard endpoint, no auth needed)
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

# Run the test suite
EXIT_CODE=0
docker compose run --rm test-runner || EXIT_CODE=$?

# Cleanup unless --keep
if [ "$KEEP" = false ]; then
    docker compose down -v
fi

exit $EXIT_CODE
