#!/bin/bash
# Install tests for the .deb, run as root on a host booted with systemd:
# the CI runner, or a privileged container running /sbin/init.
#
#   deb-upgrade.sh upgrade <released-1.8.0.deb> <new.deb>
#   deb-upgrade.sh clean <new.deb>
#
# `upgrade` reproduces a host affected by the ownership defect fixed in
# 1.9.0: a 1.8.0 package, built by CI as the `runner` account (uid 1001),
# installed on a host where that account exists. The new package must
# reset every shipped path to root, leave the service stopped and say
# which paths it repaired; started by hand, the node must record the
# certificate it serves; reinstalled on the now healthy host, it must be
# restarted as usual. Reinstalled again from each other state an operator
# can leave the service in, that state must survive: stopped and
# disabled, stopped and enabled, running and disabled. No reinstall may
# change the owner of what the node's account owns below its data
# directory. Removed, stopped. On the way, the new CLI must pin the
# certificate the running 1.8.0 node serves, which writes no
# served-certificate record.
#
# `clean` installs the new package on a host that never had lorica: no
# warning, the service active and enabled, every shipped path root's.
set -uo pipefail

SERVED_CERT=/var/lib/lorica/management/served-cert.pem

fail() {
    echo "FAIL: $*"
    exit 1
}

# Wait for the service to be active and, unless $1 says otherwise, for the
# node to have recorded the certificate it serves (1.9.0 and later).
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

# Every path the package ships outside its data directory whose owner is
# not root, one per line.
not_root_owned() {
    dpkg-query -L lorica | while IFS= read -r path; do
        case "$path" in /var/lib/lorica|/var/lib/lorica/*) continue ;; esac
        [ -e "$path" ] || [ -L "$path" ] || continue
        owner=$(stat -c %u:%g "$path")
        [ "$owner" = "0:0" ] || echo "$path $owner"
    done
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
    dpkg -i "$new" > /tmp/lorica-state.out 2>&1 || { cat /tmp/lorica-state.out; fail "reinstall"; }
    if [ "$activity" = active ]; then
        wait_active || fail "$enablement and $activity: not running after the reinstall"
    else
        sleep 2
        [ "$(systemctl is-active lorica.service)" != active ] \
            || fail "$enablement and $activity: started by the reinstall"
        grep -q "left stopped" /tmp/lorica-state.out \
            || { cat /tmp/lorica-state.out; fail "$enablement and $activity: no note that it was left stopped"; }
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
    getent passwd 1001 > /dev/null || useradd -u 1001 -m runner

    echo "=== install the released 1.8.0"
    dpkg -i "$old" > /tmp/lorica-old.out 2>&1 || { cat /tmp/lorica-old.out; fail "1.8.0 install"; }
    wait_active without-record || fail "1.8.0 did not start"
    owner=$(stat -c %u:%g /usr/share/doc/lorica)
    echo "precondition: /usr/share/doc/lorica is $owner"
    [ "$owner" != "0:0" ] || fail "1.8.0 left /usr/share/doc/lorica root-owned: the repair is not exercised"
    [ ! -e "$SERVED_CERT" ] || fail "a 1.8.0 node wrote $SERVED_CERT"

    echo "=== the new CLI against the running 1.8.0 node"
    local extracted
    extracted=$(mktemp -d)
    dpkg-deb -x "$new" "$extracted"
    # The unban answer does not matter: reaching the node's handler proves
    # the pin accepted the certificate it serves and the login went
    # through.
    "$extracted/usr/bin/lorica" --data-dir /var/lib/lorica unban 192.0.2.10 \
        --user admin --password-file /var/lib/lorica/initial-admin-password \
        > /tmp/lorica-cli.out 2>&1
    cat /tmp/lorica-cli.out
    grep -q "pinning /var/lib/lorica/management/cert.pem" /tmp/lorica-cli.out \
        || fail "the CLI did not pin the certificate a 1.8.0 node serves"
    if grep -qE "did not present the certificate|Cannot connect|Login failed" /tmp/lorica-cli.out; then
        fail "the CLI did not log in to the 1.8.0 node"
    fi

    echo "=== upgrade to the new package"
    dpkg -i "$new" > /tmp/lorica-new.out 2>&1
    rc=$?
    cat /tmp/lorica-new.out
    [ "$rc" = 0 ] || fail "dpkg -i exited $rc"
    grep -q "WARNING: lorica was NOT started" /tmp/lorica-new.out || fail "no warning on a repaired host"
    grep -qx "    /usr/share/doc/lorica" /tmp/lorica-new.out || fail "the repaired path is not listed"
    if grep -q "installed successfully" /tmp/lorica-new.out; then
        fail "the success banner on a repaired host"
    fi
    [ "$(systemctl is-active lorica.service)" != active ] || fail "the service was started on a repaired host"
    bad=$(not_root_owned)
    [ -z "$bad" ] || fail "not owned by root: $bad"
    echo "stopped, and every shipped path is 0:0"
    echo "dpkg --verify lorica: $(dpkg --verify lorica)"

    echo "=== the operator starts it"
    systemctl daemon-reload
    systemctl enable --now lorica.service
    wait_active || fail "the new version did not start, or recorded no served certificate"
    echo "active, $SERVED_CERT written"

    echo "=== reinstall on the now healthy host"
    pid_before=$(systemctl show -p MainPID --value lorica.service)
    dpkg -i "$new" > /tmp/lorica-again.out 2>&1 || { cat /tmp/lorica-again.out; fail "reinstall"; }
    if grep -q "WARNING" /tmp/lorica-again.out; then fail "a warning on a healthy host"; fi
    grep -q "installed successfully" /tmp/lorica-again.out || fail "no banner on a healthy host"
    wait_active || fail "not active after the reinstall"
    pid_after=$(systemctl show -p MainPID --value lorica.service)
    [ "$pid_before" != "$pid_after" ] || fail "not restarted"
    [ "$(systemctl is-enabled lorica.service)" = enabled ] || fail "not enabled"
    echo "restarted ($pid_before -> $pid_after) and enabled"

    echo "=== an upgrade keeps the state the operator left"
    keeps_state disabled inactive "$new"
    keeps_state enabled inactive "$new"
    keeps_state disabled active "$new"

    echo "=== remove"
    dpkg -r lorica > /dev/null 2>&1 || fail "remove"
    [ "$(systemctl is-active lorica.service)" != active ] || fail "still active after remove"
    echo "stopped"
}

clean() {
    local new="$1"
    echo "=== install on a host that never had lorica"
    dpkg -i "$new" > /tmp/lorica-new.out 2>&1 || { cat /tmp/lorica-new.out; fail "install"; }
    cat /tmp/lorica-new.out
    if grep -q "WARNING" /tmp/lorica-new.out; then fail "a warning on a clean host"; fi
    grep -q "installed successfully" /tmp/lorica-new.out || fail "no banner"
    wait_active || fail "not active, or recorded no served certificate"
    [ "$(systemctl is-enabled lorica.service)" = enabled ] || fail "not enabled"
    bad=$(not_root_owned)
    [ -z "$bad" ] || fail "not owned by root: $bad"
    echo "active, enabled, $SERVED_CERT written, every shipped path 0:0"
}

case "${1:-}" in
    upgrade) [ $# -eq 3 ] || fail "usage: $0 upgrade <old.deb> <new.deb>"; upgrade "$2" "$3" ;;
    clean) [ $# -eq 2 ] || fail "usage: $0 clean <new.deb>"; clean "$2" ;;
    *) fail "usage: $0 upgrade <old.deb> <new.deb> | clean <new.deb>" ;;
esac
echo "PASS: $1"
