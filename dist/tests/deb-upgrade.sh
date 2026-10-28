#!/bin/bash
# Install tests for the .deb, run as root on a host booted with systemd:
# the CI runner, or a privileged container running /sbin/init.
#
#   deb-upgrade.sh upgrade <released-old.deb> <new.deb>
#   deb-upgrade.sh upgrade-held <released-old.deb> <new.deb>
#   deb-upgrade.sh clean <new.deb>
#
# The old package is a released one, 1.8.0 or 1.6.0, called "the old
# version" below. Every package up to 1.8.0 was built by CI as the
# `runner` account (uid 1001) and recorded it as the owner of every
# entry, and its prerm stopped and disabled the service on every
# upgrade. Both upgrade scenarios install the old version and upgrade it
# to the new package, which must reset every shipped path to root either
# way. 1.6.0 is there for its access-log.db, whose schema every release
# from 1.7.0 to 1.9.1 failed to open: the old node writes audit rows
# before the upgrade, and every node the new package starts must have
# persistence (persistence.sh), whatever version wrote its files.
#
# `upgrade` runs where no account has uid 1001 or the name `runner`, as
# on most hosts upgraded from an official .deb: nobody could have
# written those paths, so the new package must repair them without a
# word and enable and start the service, as the old version's own postinst did.
# The script refuses to run where such an account exists: on the CI
# runner, which has one, it runs in a container.
#
# `upgrade-held` runs where an account has uid 1001 (one is created when
# none exists): that account could have changed the paths, so the new
# package must leave the service stopped and name the paths it repaired
# and the account that could write them; started by hand, the node must
# record the certificate it serves.
#
# Both then reinstall the new package on the now healthy host, which
# must restart it as usual, and reinstall it again from each other state
# an operator can leave the service in, which must survive: stopped and
# disabled, stopped and enabled, running and disabled. No reinstall may
# change the owner of what the node's account owns below its data
# directory. Removed, stopped. On the way, the new CLI must pin the
# certificate the running old node serves, which writes no
# served-certificate record. `upgrade` last installs the old version
# again, stops and disables it, and upgrades again: enabled and started,
# as every upgrade from those versions did, whatever a stale state
# record says.
#
# `clean` installs the new package on a host that never had lorica: no
# warning, the service active and enabled, every shipped path root's.
#
# The new package is always installed with `apt-get install`, never
# `dpkg -i`: it depends on libgssapi-krb5-2, which apt resolves from the
# archive the way an operator's install does and dpkg would leave
# unconfigured. Released packages keep `dpkg -i`, as they were installed.
# After every install of the new package, its binaries must resolve
# every library and start.
set -uo pipefail

SERVED_CERT=/var/lib/lorica/management/served-cert.pem

fail() {
    echo "FAIL: $*"
    exit 1
}

# shellcheck source=persistence.sh
. "$(dirname "$0")/persistence.sh"

APT_LISTS_FRESH=false

refresh_apt_lists() {
    [ "$APT_LISTS_FRESH" = true ] && return 0
    apt-get update -qq > /tmp/lorica-apt-update.out 2>&1 \
        || { cat /tmp/lorica-apt-update.out; fail "apt-get update"; }
    APT_LISTS_FRESH=true
}

# Install the new package through apt, output in $2. apt takes a local
# file only by a path it can tell from a package name, hence the
# absolute one; --reinstall makes it act on a version already installed
# as dpkg -i did. apt runs the maintainer scripts on a pseudo-terminal,
# whose CR LF line ends would defeat the whole-line greps on their output.
install_new() {
    local new="$1" out="$2"
    refresh_apt_lists
    DEBIAN_FRONTEND=noninteractive apt-get install -y --reinstall "$(realpath "$new")" 2>&1 \
        | tr -d '\r' > "$out"
}

# The new package's Depends, installed alone: its CLI runs from an
# extracted copy before the package is, and links what the package
# depends on.
install_new_dependencies() {
    local new="$1" packages
    packages=$(dpkg-deb -f "$new" Depends | sed 's/([^)]*)//g; s/|[^,]*//g; s/,/ /g')
    refresh_apt_lists
    # shellcheck disable=SC2086 # one word per package
    DEBIAN_FRONTEND=noninteractive apt-get install -y $packages > /tmp/lorica-deps.out 2>&1 \
        || { cat /tmp/lorica-deps.out; fail "installing the new package's dependencies: $packages"; }
}

binaries_run() {
    ldd /usr/bin/lorica /usr/bin/lorica-mcp | grep -q 'not found' \
        && { ldd /usr/bin/lorica /usr/bin/lorica-mcp; fail "an unresolved library"; }
    /usr/bin/lorica --version || fail "lorica --version"
    echo "every library resolved, GSS-API from $(ldd /usr/bin/lorica | awk '/libgssapi_krb5/ {print $3}')"
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
    install_new "$new" /tmp/lorica-state.out || { cat /tmp/lorica-state.out; fail "reinstall"; }
    if [ "$activity" = active ]; then
        wait_active || fail "$enablement and $activity: not running after the reinstall"
        assert_persistence "$enablement and $activity"
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

# Install the released old version, check it left the defect the new
# package repairs, point the new CLI at the running node, and count the
# audit rows it wrote.
install_old() {
    local old="$1" new="$2"
    echo "=== install the released $OLD"
    dpkg -i "$old" > /tmp/lorica-old.out 2>&1 || { cat /tmp/lorica-old.out; fail "$OLD install"; }
    wait_active without-record || fail "$OLD did not start"
    owner=$(stat -c %u:%g /usr/share/doc/lorica)
    echo "precondition: /usr/share/doc/lorica is $owner"
    [ "$owner" != "0:0" ] || fail "$OLD left /usr/share/doc/lorica root-owned: the repair is not exercised"
    [ ! -e "$SERVED_CERT" ] || fail "a $OLD node wrote $SERVED_CERT"

    echo "=== the new CLI against the running $OLD node"
    local extracted
    extracted=$(mktemp -d)
    dpkg-deb -x "$new" "$extracted"
    install_new_dependencies "$new"
    # The unban answer does not matter: reaching the node's handler proves
    # the pin accepted the certificate it serves and the login went
    # through.
    "$extracted/usr/bin/lorica" --data-dir /var/lib/lorica unban 192.0.2.10 \
        --user admin --password-file /var/lib/lorica/initial-admin-password \
        > /tmp/lorica-cli.out 2>&1
    cat /tmp/lorica-cli.out
    grep -q "pinning /var/lib/lorica/management/cert.pem" /tmp/lorica-cli.out \
        || fail "the CLI did not pin the certificate a $OLD node serves"
    if grep -qE "did not present the certificate|Cannot connect|Login failed" /tmp/lorica-cli.out; then
        fail "the CLI did not log in to the $OLD node"
    fi
    record_old_audit_rows "$OLD"
}

# The new package on a host it has already repaired: a reinstall restarts
# a running service, every other state survives, and a removal stops it.
healthy_host() {
    local new="$1"
    echo "=== reinstall on the now healthy host"
    pid_before=$(systemctl show -p MainPID --value lorica.service)
    install_new "$new" /tmp/lorica-again.out || { cat /tmp/lorica-again.out; fail "reinstall"; }
    if grep -q "WARNING" /tmp/lorica-again.out; then fail "a warning on a healthy host"; fi
    grep -q "installed successfully" /tmp/lorica-again.out || fail "no banner on a healthy host"
    wait_active || fail "not active after the reinstall"
    pid_after=$(systemctl show -p MainPID --value lorica.service)
    [ "$pid_before" != "$pid_after" ] || fail "not restarted"
    [ "$(systemctl is-enabled lorica.service)" = enabled ] || fail "not enabled"
    echo "restarted ($pid_before -> $pid_after) and enabled"
    assert_persistence "reinstall on a healthy host"

    echo "=== an upgrade keeps the state the operator left"
    keeps_state disabled inactive "$new"
    keeps_state enabled inactive "$new"
    keeps_state disabled active "$new"

    echo "=== remove"
    dpkg -r lorica > /dev/null 2>&1 || fail "remove"
    [ "$(systemctl is-active lorica.service)" != active ] || fail "still active after remove"
    echo "stopped"
}

# The upgrade from the old version where nobody could have written the
# shipped paths: repaired silently, enabled and started, with persistence.
upgrade_from_old_unheld() {
    local new="$1" label="$2"
    install_new "$new" /tmp/lorica-new.out
    rc=$?
    cat /tmp/lorica-new.out
    [ "$rc" = 0 ] || fail "$label: apt-get install exited $rc"
    binaries_run
    if grep -q "WARNING" /tmp/lorica-new.out; then fail "$label: a warning where no account could write the paths"; fi
    if grep -q "left stopped" /tmp/lorica-new.out; then fail "$label: left stopped"; fi
    grep -q "installed successfully" /tmp/lorica-new.out || fail "$label: no banner"
    wait_active || fail "$label: not active, or recorded no served certificate"
    [ "$(systemctl is-enabled lorica.service)" = enabled ] || fail "$label: not enabled"
    bad=$(not_root_owned)
    [ -z "$bad" ] || fail "$label: not owned by root: $bad"
    echo "$label: active, enabled, $SERVED_CERT written, every shipped path 0:0"
    echo "dpkg --verify lorica: $(dpkg --verify lorica)"
    assert_persistence "$label"
}

upgrade() {
    local old="$1" new="$2"
    if getent passwd 1001 > /dev/null || getent passwd runner > /dev/null; then
        fail "this host has a uid-1001 or runner account; run \`upgrade\` where neither exists"
    fi
    install_old "$old" "$new"

    echo "=== upgrade to the new package, no account could write the shipped paths"
    upgrade_from_old_unheld "$new" "upgrade from $OLD"

    healthy_host "$new"

    echo "=== a $OLD node stopped and disabled by the operator, upgraded"
    dpkg -i "$old" > /tmp/lorica-old.out 2>&1 || { cat /tmp/lorica-old.out; fail "$OLD reinstall"; }
    wait_active without-record || fail "$OLD did not start"
    systemctl disable --now lorica.service > /dev/null 2>&1
    # No $OLD script writes or reads this record, so one found by the
    # upgrade is stale, left by a 1.9.x transaction that never reached its
    # postinst. Plant one saying the service was stopped: it must be
    # ignored.
    printf 'inactive\n' > /run/lorica-package.state
    upgrade_from_old_unheld "$new" "upgrade from a disabled $OLD"
    dpkg -r lorica > /dev/null 2>&1 || fail "remove"
}

upgrade_held() {
    local old="$1" new="$2"
    getent passwd 1001 > /dev/null || useradd -u 1001 -m runner
    local account
    account=$(getent passwd 1001 | cut -d: -f1)
    install_old "$old" "$new"

    echo "=== upgrade to the new package, $account (uid 1001) could write the shipped paths"
    install_new "$new" /tmp/lorica-new.out
    rc=$?
    cat /tmp/lorica-new.out
    [ "$rc" = 0 ] || fail "apt-get install exited $rc"
    binaries_run
    grep -q "WARNING: lorica was NOT started" /tmp/lorica-new.out || fail "no warning on a repaired host"
    grep -qx "    /usr/share/doc/lorica" /tmp/lorica-new.out || fail "the repaired path is not listed"
    grep -qx "    the account $account (uid 1001)" /tmp/lorica-new.out \
        || fail "the account that could write the paths is not named"
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
    assert_persistence "upgrade from $OLD, started by the operator"

    healthy_host "$new"
}

clean() {
    local new="$1"
    echo "=== install on a host that never had lorica"
    install_new "$new" /tmp/lorica-new.out || { cat /tmp/lorica-new.out; fail "install"; }
    cat /tmp/lorica-new.out
    binaries_run
    if grep -q "WARNING" /tmp/lorica-new.out; then fail "a warning on a clean host"; fi
    grep -q "installed successfully" /tmp/lorica-new.out || fail "no banner"
    wait_active || fail "not active, or recorded no served certificate"
    [ "$(systemctl is-enabled lorica.service)" = enabled ] || fail "not enabled"
    bad=$(not_root_owned)
    [ -z "$bad" ] || fail "not owned by root: $bad"
    echo "active, enabled, $SERVED_CERT written, every shipped path 0:0"
}

usage="usage: $0 upgrade|upgrade-held <old.deb> <new.deb> | clean <new.deb>"
case "${1:-}" in
    upgrade|upgrade-held)
        [ $# -eq 3 ] || fail "$usage"
        OLD=$(dpkg-deb -f "$2" Version)
        ;;
esac
case "${1:-}" in
    upgrade) [ $# -eq 3 ] || fail "$usage"; upgrade "$2" "$3" ;;
    upgrade-held) [ $# -eq 3 ] || fail "$usage"; upgrade_held "$2" "$3" ;;
    clean) [ $# -eq 2 ] || fail "$usage"; clean "$2" ;;
    *) fail "$usage" ;;
esac
echo "PASS: $1"
