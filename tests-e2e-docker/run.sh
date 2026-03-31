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

# Wait a moment for Lorica to start
echo "Waiting for Lorica to initialize..."
sleep 5

# Run the test suite
EXIT_CODE=0
docker compose run --rm test-runner || EXIT_CODE=$?

# Cleanup unless --keep
if [ "$KEEP" = false ]; then
    docker compose down -v
fi

exit $EXIT_CODE
