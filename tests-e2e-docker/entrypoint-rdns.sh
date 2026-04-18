#!/bin/sh
# =============================================================================
# Lorica rDNS E2E entrypoint (v1.4.0 Epic 3 follow-up).
#
# Points the container's resolver at the `dnsmasq` sidecar so hickory-
# resolver inside Lorica picks up the test zone from /etc/resolv.conf
# at RdnsResolver::from_system_conf(). Reuses the default Lorica image;
# the only runtime variation from entrypoint.sh is the resolv.conf
# override.
#
# Design note: we do NOT override /etc/hosts. Lorica's bot-protection
# rDNS path uses hickory-resolver, which reads /etc/resolv.conf to
# find nameservers and ignores /etc/hosts. Writing PTR records into
# hosts would not help.
# =============================================================================
set -e

# docker-compose resolves `dnsmasq` to its service IP on the `e2e`
# network; write that address into resolv.conf so the standard
# read_system_conf() picks it up.
DNSMASQ_IP=$(getent hosts dnsmasq | awk '{print $1}')
if [ -z "$DNSMASQ_IP" ]; then
    echo "ERROR: dnsmasq sidecar unreachable — profile 'rdns' requires it" >&2
    exit 1
fi
cat > /etc/resolv.conf <<EOF
nameserver $DNSMASQ_IP
options timeout:2 attempts:2
EOF
echo "rDNS entrypoint: resolv.conf points at dnsmasq ($DNSMASQ_IP)"

mkdir -p /shared

socat TCP-LISTEN:9443,fork,reuseaddr TCP:127.0.0.1:19443 &

LOGFILE=/shared/lorica.log
: > "$LOGFILE"

lorica --data-dir /var/lib/lorica --management-port 19443 \
    > "$LOGFILE" 2>&1 &
LORICA_PID=$!

# Scrape the bootstrap admin password out of the boot log so the
# test runner can log in without knowing it in advance.
for i in $(seq 1 30); do
    if grep -q "Initial admin password:" "$LOGFILE" 2>/dev/null; then
        PW=$(grep "Initial admin password:" "$LOGFILE" | sed 's/.*Initial admin password: //')
        echo "$PW" > /shared/admin_password
        break
    fi
    sleep 1
done

cat "$LOGFILE"
tail -f "$LOGFILE" &

wait "$LORICA_PID"
