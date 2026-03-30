#!/bin/sh
# E2E test entrypoint: socat forwards external 0.0.0.0:9443 to Lorica's
# localhost-only management API. This keeps the production security model
# (localhost binding) intact while allowing Docker port mapping.

socat TCP-LISTEN:9443,fork,reuseaddr TCP:127.0.0.1:19443 &

exec su -s /bin/sh lorica -c \
  "lorica --data-dir /var/lib/lorica --management-port 19443"
