#!/bin/sh
# Runs one scenario inside the netem container.
#   LABEL=name NETEM="delay 2ms 1ms loss 1% reorder 5%" NETEM_UDP=0 \
#     sh run.sh --upgrades 50 --interval-ms 200 ...
# TCP over the container's loopback always goes through netem; UDP only
# with NETEM_UDP=1. Logs are copied to /out/$LABEL when /out is mounted.
set -u
BIN=${BIN:-/tmp/target/s1216/release/spike-12-16-live-transfer}
LABEL=${LABEL:-run}
NETEM=${NETEM:-delay 2ms 1ms loss 1% reorder 5%}
ip link set lo mtu 1500
tc qdisc add dev lo root handle 1: prio bands 3 priomap 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1
# shellcheck disable=SC2086
tc qdisc add dev lo parent 1:1 handle 10: netem $NETEM
tc filter add dev lo parent 1: protocol ip prio 1 u32 match ip protocol 6 0xff flowid 1:1
if [ "${NETEM_UDP:-0}" = 1 ]; then
  tc filter add dev lo parent 1: protocol ip prio 2 u32 match ip protocol 17 0xff flowid 1:1
fi
echo "netem: $NETEM (udp: ${NETEM_UDP:-0}); kernel $(uname -r); $(nproc) cpus"
nstat -n >/dev/null 2>&1
"$BIN" harness --label "$LABEL" --dir /tmp/run "$@"
rc=$?
echo "kernel counters during the run:"
nstat -z TcpRetransSegs TcpExtTCPLostRetransmit TcpExtTCPSackRecovery TcpExtTCPOFOQueue TcpExtTCPZeroWindowDrop UdpRcvbufErrors UdpInErrors 2>/dev/null | tail -n +2
tc -s qdisc show dev lo | grep -A1 "netem"
if [ -d /out ]; then
  rm -rf "/out/$LABEL"
  cp -r /tmp/run "/out/$LABEL"
fi
exit $rc
