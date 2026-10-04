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
# and be restarted. Reinstalled again from each other state an operator
# can leave the service in, that state must survive: stopped and
# disabled, stopped and enabled, running and disabled. No reinstall may
# change the owner of what the node's account owns below its data
# directory. Erased, it must be stopped. Last, a 1.8.0 node the operator
# stopped and disabled is upgraded: it must stay stopped and disabled,
# although the 1.8.0 preun disables it on the way out whatever its state.
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

# Put the service in the given enablement and activity, reinstall `new`
# over it, and require both unchanged. A probe file the node's account
# does not own, below the data directory, must keep its owner: the
# package chowns the directories it ships, not the tree under them.
keeps_state() {
    local enablement="$1" activity="$2" new="$3"
    local probe=/var/lib/lorica/exported-certs/owner-probe
    case "$enablement" in
        enabled) systemctl enable lorica.service > /dev/null 2>&1 ;;
        disabled) systemctl disable lorica.service > /dev/null 2>&1 ;;
    esac
    if [ "$activity" = active ]; then
        systemctl start lorica.service
        wait_active || fail "did not start before the reinstall"
    else
        systemctl stop lorica.service
    fi
    touch "$probe"
    chown 0:0 "$probe"
    install_quietly -Uvh --replacepkgs --nosignature "$new"
    if [ "$activity" = active ]; then
        wait_active || fail "$enablement and $activity: not running after the reinstall"
    else
        sleep 2
        [ "$(systemctl is-active lorica.service)" != active ] \
            || fail "$enablement and $activity: started by the reinstall"
        grep -q "left stopped" /tmp/lorica-rpm.out \
            || { cat /tmp/lorica-rpm.out; fail "$enablement and $activity: no note that it was left stopped"; }
    fi
    [ "$(systemctl is-enabled lorica.service)" = "$enablement" ] \
        || fail "$enablement and $activity: now $(systemctl is-enabled lorica.service)"
    [ "$(stat -c %u:%g "$probe")" = "0:0" ] \
        || fail "the reinstall changed the owner of $probe to $(stat -c %u:%g "$probe")"
    rm -f "$probe"
    echo "$enablement and $activity: kept"
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

    echo "=== an upgrade keeps the state the operator left"
    keeps_state disabled inactive "$new"
    keeps_state enabled inactive "$new"
    keeps_state disabled active "$new"

    echo "=== erase"
    rpm -e lorica > /tmp/lorica-rpm.out 2>&1 || { cat /tmp/lorica-rpm.out; fail "erase"; }
    [ "$(systemctl is-active lorica.service)" != active ] || fail "still active after erase"
    echo "stopped"

    echo "=== a 1.8.0 node stopped and disabled by the operator, upgraded"
    install_quietly -ivh --nosignature "$old"
    wait_active without-record || fail "1.8.0 did not start"
    systemctl disable --now lorica.service > /dev/null 2>&1
    install_quietly -Uvh --nosignature "$new"
    sleep 2
    [ "$(systemctl is-active lorica.service)" != active ] || fail "the upgrade started a stopped 1.8.0 node"
    [ "$(systemctl is-enabled lorica.service)" = disabled ] || fail "the upgrade enabled a disabled 1.8.0 node"
    echo "stopped and disabled, as left"
    rpm -e lorica > /dev/null 2>&1 || fail "erase"
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
