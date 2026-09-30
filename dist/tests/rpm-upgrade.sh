#!/bin/bash
# Install tests for the .rpm, run as root on a host booted with systemd
# (in CI and locally: a privileged Fedora container running /sbin/init).
#
#   rpm-upgrade.sh upgrade <released-1.8.0.rpm> <new.rpm>
#   rpm-upgrade.sh clean <new.rpm>
#
# `upgrade` installs 1.8.0, whose preun stops and disables the service on
# every upgrade, and upgrades to the new package: its posttrans must bring
# the service back, enabled, on the new binary. The new package is then
# reinstalled over itself, which runs its own preun with $1 = 1 exactly
# as an upgrade to the next version does: the service must stay enabled
# and be restarted. Erased, it must be stopped.
#
# `clean` installs the new package on a host that never had lorica.
set -uo pipefail

SERVED_CERT=/var/lib/lorica/management/served-cert.pem

fail() {
    echo "FAIL: $*"
    exit 1
}

wait_active() {
    for _ in $(seq 1 60); do
        if [ "$(systemctl is-active lorica.service)" = active ] \
            && { [ "${1:-}" = without-record ] || [ -s "$SERVED_CERT" ]; }; then
            return 0
        fi
        sleep 1
    done
    systemctl status lorica.service --no-pager | tail -20
    journalctl -u lorica.service --no-pager | tail -30
    return 1
}

# rpm reports a failed scriptlet as a warning and still exits 0.
install_quietly() {
    rpm "$@" > /tmp/lorica-rpm.out 2>&1 || { cat /tmp/lorica-rpm.out; fail "rpm $*"; }
    if grep -qi "scriptlet" /tmp/lorica-rpm.out; then
        cat /tmp/lorica-rpm.out
        fail "a scriptlet failed: rpm $*"
    fi
}

upgrade() {
    local old="$1" new="$2"
    echo "=== install the released 1.8.0"
    install_quietly -ivh --nosignature "$old"
    wait_active without-record || fail "1.8.0 did not start"

    echo "=== upgrade to the new package"
    install_quietly -Uvh --nosignature "$new"
    wait_active || fail "not active after the upgrade from 1.8.0, or no served certificate"
    [ "$(systemctl is-enabled lorica.service)" = enabled ] || fail "not enabled after the upgrade from 1.8.0"
    echo "active and enabled, $SERVED_CERT written"

    echo "=== reinstall over itself (its own preun runs with \$1 = 1)"
    pid_before=$(systemctl show -p MainPID --value lorica.service)
    install_quietly -Uvh --replacepkgs --nosignature "$new"
    wait_active || fail "not active after the reinstall"
    [ "$(systemctl is-enabled lorica.service)" = enabled ] || fail "not enabled after the reinstall"
    pid_after=$(systemctl show -p MainPID --value lorica.service)
    [ "$pid_before" != "$pid_after" ] || fail "not restarted"
    echo "restarted ($pid_before -> $pid_after) and enabled"

    echo "=== erase"
    rpm -e lorica > /tmp/lorica-rpm.out 2>&1 || { cat /tmp/lorica-rpm.out; fail "erase"; }
    [ "$(systemctl is-active lorica.service)" != active ] || fail "still active after erase"
    echo "stopped"
}

clean() {
    local new="$1"
    echo "=== install on a host that never had lorica"
    install_quietly -ivh --nosignature "$new"
    grep -q "served-cert.pem" /tmp/lorica-rpm.out || fail "the banner does not name the served certificate"
    wait_active || fail "not active, or no served certificate"
    [ "$(systemctl is-enabled lorica.service)" = enabled ] || fail "not enabled"
    echo "active and enabled, $SERVED_CERT written"
}

case "${1:-}" in
    upgrade) [ $# -eq 3 ] || fail "usage: $0 upgrade <old.rpm> <new.rpm>"; upgrade "$2" "$3" ;;
    clean) [ $# -eq 2 ] || fail "usage: $0 clean <new.rpm>"; clean "$2" ;;
    *) fail "usage: $0 upgrade <old.rpm> <new.rpm> | clean <new.rpm>" ;;
esac
echo "PASS: $1"
