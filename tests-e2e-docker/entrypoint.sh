#!/bin/sh
# E2E test entrypoint: socat forwards external 0.0.0.0:9443 to Lorica's
# localhost-only management API. The admin password is captured from Lorica's
# first-run output and written to /shared/admin_password for the test runner.

mkdir -p /shared

socat TCP-LISTEN:9443,fork,reuseaddr TCP:127.0.0.1:19443 &

# Run Lorica, capture output, extract password
exec su -s /bin/sh lorica -c \
  "lorica --data-dir /var/lib/lorica --management-port 19443" 2>&1 | \
  while IFS= read -r line; do
    echo "$line"
    case "$line" in
      *"Initial admin password:"*)
        pw=$(echo "$line" | sed 's/.*Initial admin password: //')
        if [ -n "$pw" ]; then
          echo "$pw" > /shared/admin_password
        fi
        ;;
    esac
  done
