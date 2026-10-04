#!/usr/bin/env bash
# Build a .deb package for Lorica.
# Usage: bash dist/build-deb.sh [binary_path] [mcp_binary_path]
#   binary_path defaults to ./lorica (current directory)
#   mcp_binary_path defaults to lorica-mcp next to binary_path, which is
#   where `cargo build --release -p lorica -p lorica-mcp` leaves both

set -euo pipefail
cd "$(dirname "$0")/.."

BINARY="${1:-./lorica}"
MCP_BINARY="${2:-$(dirname "$BINARY")/lorica-mcp}"
VERSION=$(grep '^version' lorica/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/' | tr -d '\r')
ARCH="amd64"
PKG_NAME="lorica_${VERSION}_${ARCH}"
PKG_DIR="dist/${PKG_NAME}"

echo "Building .deb package: lorica ${VERSION} (${ARCH})"

# Create package structure
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/lib/systemd/system"
mkdir -p "$PKG_DIR/usr/share/doc/lorica"
mkdir -p "$PKG_DIR/var/lib/lorica"
# The hot-upgrade staging zone /var/lib/lorica/upgrade (Story 8.4) is
# created 0700 at runtime by the upgrade endpoint - do NOT pre-create it
# here. No signing key is bundled either: the Ed25519 public key is
# operator-managed (the operator sets `upgrade_signing_pubkey_path`, e.g.
# to /etc/lorica/upgrade-signing.pub). See docs/hot-upgrade.md.

# Copy binary
cp "$BINARY" "$PKG_DIR/usr/bin/lorica"
chmod 755 "$PKG_DIR/usr/bin/lorica"

# The MCP server (Story 11.4). Installed, never started by the package:
# the operator's MCP client launches it. See the note in lorica.service.
cp "$MCP_BINARY" "$PKG_DIR/usr/bin/lorica-mcp"
chmod 755 "$PKG_DIR/usr/bin/lorica-mcp"

# Copy systemd service
cp dist/lorica.service "$PKG_DIR/lib/systemd/system/"
chmod 644 "$PKG_DIR/lib/systemd/system/lorica.service"

# Copy LICENSE and NOTICE (Apache-2.0 section 4(d) compliance)
cp LICENSE "$PKG_DIR/usr/share/doc/lorica/"
cp NOTICE "$PKG_DIR/usr/share/doc/lorica/"
chmod 644 "$PKG_DIR/usr/share/doc/lorica/LICENSE"
chmod 644 "$PKG_DIR/usr/share/doc/lorica/NOTICE"

# Debian requires a copyright file summarizing the licensing
cat > "$PKG_DIR/usr/share/doc/lorica/copyright" << 'EOF'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: Lorica
Upstream-Contact: Romain G. <noreply@github.com>
Source: https://github.com/Rwx-G/Lorica

Files: *
Copyright: 2026 Romain G.
License: Apache-2.0

Files: lorica-core/* lorica-proxy/* lorica-http/* lorica-error/*
 lorica-pool/* lorica-runtime/* lorica-timeout/* lorica-tls/*
 lorica-lb/* lorica-ketama/* lorica-limits/* lorica-header-serde/*
 lorica-cache/* lorica-memory-cache/* lorica-lru/* tinyufo/*
Copyright: 2024-2026 Cloudflare, Inc.
License: Apache-2.0
Comment: Forked from Cloudflare Pingora (https://github.com/cloudflare/pingora).
 See /usr/share/doc/lorica/NOTICE for attribution.

License: Apache-2.0
 On Debian systems, the complete text of the Apache License 2.0 can be
 found in /usr/share/doc/lorica/LICENSE or /usr/share/common-licenses/Apache-2.0.
EOF
chmod 644 "$PKG_DIR/usr/share/doc/lorica/copyright"

# Control file
cat > "$PKG_DIR/DEBIAN/control" << EOF
Package: lorica
Version: ${VERSION}
Section: net
Priority: optional
Architecture: ${ARCH}
Maintainer: Romain G. <noreply@github.com>
Description: Modern reverse proxy with built-in dashboard
 A dashboard-first reverse proxy built in Rust. Single binary,
 embedded web UI, no config files. HTTP/HTTPS proxying, WAF,
 health checks, certificate management, Prometheus metrics.
 Also ships lorica-mcp, the MCP server an operator's MCP client
 launches; no service starts it.
Homepage: https://github.com/Rwx-G/Lorica
Depends: ca-certificates
EOF

# /run/lorica-package.state carries the service state across a
# transaction: written by the old package's prerm on an upgrade, or by
# preinst on an install, and consumed by postinst. /run belongs to root,
# so the service account cannot plant a record, and it is cleared at
# boot, so a record an aborted transaction left behind dies with it.

# Pre-install script. `install` is a first install, or a reinstall after
# `dpkg -r` (whose prerm disabled the service): both get first-install
# behaviour. An upgrade keeps what the old prerm recorded.
cat > "$PKG_DIR/DEBIAN/preinst" << 'EOF'
#!/bin/sh
set -e
if [ "$1" = "install" ]; then
    printf 'install\n' > /run/lorica-package.state 2>/dev/null || true
fi
EOF
chmod 755 "$PKG_DIR/DEBIAN/preinst"

# Post-install script
cat > "$PKG_DIR/DEBIAN/postinst" << 'EOF'
#!/bin/sh
set -e

# Create system user
if ! id -u lorica >/dev/null 2>&1; then
    useradd -r -s /bin/false -d /var/lib/lorica lorica
fi

# What the service was doing before this transaction: `install` (first
# install), `active` or `inactive` (an upgrade from a package whose
# prerm recorded it), or nothing (an upgrade from 1.8.0 or earlier,
# whose prerm stopped and disabled the service and recorded nothing).
previous_state=$(cat /run/lorica-package.state 2>/dev/null || true)
rm -f /run/lorica-package.state
if [ -z "${2:-}" ]; then
    previous_state=install
fi

# Repair hosts that installed a package built before 1.9.0. Those recorded
# the CI builder's account (runner, uid 1001) as the owner of every entry,
# and an upgrade does not fix all of it: dpkg rewrites the owner of each
# file it replaces, but keeps the owner of a directory that already exists
# (/usr/share/doc/lorica, and /lib/systemd/system on a host where lorica
# created it). Every path this package ships outside its data directory
# belongs to root, so any other owner found here is that defect. Only the
# offending entries are touched, which keeps this a no-op on a clean host,
# and each one is printed below.
#
# The file list is read first and on its own: /bin/sh has no pipefail, so
# a failing dpkg-query piped into the loop would read as nothing to repair.
package_paths=$(dpkg-query -L lorica) || {
    echo "lorica: cannot list the package's files (dpkg-query -L lorica)," \
        "so their ownership cannot be checked" >&2
    exit 1
}
repaired=$(printf '%s\n' "$package_paths" | while IFS= read -r path; do
    case "$path" in
        /var/lib/lorica|/var/lib/lorica/*) continue ;;
    esac
    [ -e "$path" ] || [ -L "$path" ] || continue
    [ "$(stat -c %u:%g "$path")" = "0:0" ] && continue
    chown -h root:root "$path"
    if [ -d "$path" ] && [ ! -L "$path" ]; then
        chmod 755 "$path"
    elif [ -f "$path" ] && [ ! -L "$path" ]; then
        chmod go-w "$path"
    fi
    printf '%s\n' "$path"
done)

# Set permissions. Not recursive: everything below the data directory is
# the service account's, and root walking a tree that account controls
# follows whatever it planted there (a hard link to a root-owned file
# would change hands). The node creates what it writes with its own
# owner, and a recursive pass also reset, on every upgrade, the owner
# an operator gave exported certificates.
chown lorica:lorica /var/lib/lorica
chmod 750 /var/lib/lorica

# Pre-create the default cert-export zone (v1.4.1) with the
# restrictive mode the exporter uses by default. The feature is
# disabled at install time; this directory only gets files when
# the operator turns `cert_export_enabled` on via the dashboard.
# Keeping the dir pre-created lets the ReadWritePaths in the
# systemd unit take effect even before the first export, and
# makes it obvious to operators where exported bundles will land.
if [ ! -d /var/lib/lorica/exported-certs ]; then
    mkdir -p /var/lib/lorica/exported-certs
fi
chown lorica:lorica /var/lib/lorica/exported-certs
chmod 750 /var/lib/lorica/exported-certs

# A repaired host is left stopped. While those paths belonged to another
# account, that account could change them or plant entries beside them
# that no package lists: a unit, a lorica.service.d drop-in, a generator.
# A daemon-reload or a restart here would load and run them as root before
# the operator could look. The previous package's prerm already stopped
# the service, so it stays stopped until the operator starts it.
if [ -n "$repaired" ]; then
    echo ""
    echo "  ================================================"
    echo "  WARNING: lorica was NOT started."
    echo "  "
    echo "  This upgrade reset to root the owner of these paths,"
    echo "  which a package built before 1.9.0 had left owned by"
    echo "  the account that built it:"
    printf '%s\n' "$repaired" | sed 's/^/    /'
    echo "  "
    echo "  Until now that account could change them, and add"
    echo "  files beside them that no package lists. Before"
    echo "  starting the service:"
    echo "    1. sudo dpkg --verify lorica"
    echo "       (no output: the packaged files are as shipped)"
    echo "    2. look in the directories above, and in"
    echo "       /etc/systemd/system, for units, drop-ins or"
    echo "       generators you did not create"
    echo "    3. then start it:"
    echo "       sudo systemctl daemon-reload"
    echo "       sudo systemctl enable --now lorica.service"
    echo "  ================================================"
    echo ""
    exit 0
fi

# Enable and start on a first install. On an upgrade, the operator's
# choice stands: the enablement is never touched (this version's prerm
# does not disable on upgrade), and the service is restarted only if it
# was running. /run/systemd/system exists only while systemd runs;
# without it (an image build, a container) nothing is started.
systemd_running=no
if [ -d /run/systemd/system ]; then
    systemd_running=yes
    systemctl daemon-reload
fi
left_stopped=""
case "$previous_state" in
    install)
        systemctl enable lorica.service
        if [ "$systemd_running" = yes ]; then
            systemctl restart lorica.service
        fi
        ;;
    active)
        if [ "$systemd_running" = yes ]; then
            systemctl restart lorica.service
        fi
        ;;
    inactive)
        left_stopped="it was not running before the upgrade"
        ;;
    *)
        left_stopped="the package it replaced stopped and disabled it, and recorded nothing that tells a deliberate disable from that one"
        ;;
esac

echo ""
echo "  ================================================"
if [ -n "$left_stopped" ]; then
    echo "  NOTE: lorica.service was left stopped:"
    echo "    $left_stopped."
    echo "  To run it:            sudo systemctl start lorica.service"
    echo "  To run it at boot:    sudo systemctl enable lorica.service"
    echo "  "
fi
echo "  Lorica installed successfully!"
echo "  "
echo "  Dashboard: https://127.0.0.1:9443"
echo "    (TLS with a self-signed certificate; listens on"
echo "     localhost only, not reachable from other machines."
echo "     Before you log in, check that the fingerprint your"
echo "     browser shows is the one the node serves:"
echo "       sudo openssl x509 -noout -fingerprint -sha256 \\"
echo "         -in /var/lib/lorica/management/served-cert.pem"
echo "     Another local process can hold the port while"
echo "     lorica is stopped, and it would receive the password.)"
echo "  "
echo "  The initial admin password is written to a 0600 file:"
echo "    sudo cat /var/lib/lorica/initial-admin-password"
echo "    (delete it after your first login)"
echo "  "
echo "  Customize with: systemctl edit lorica"
echo "    Add an [Service] override with ExecStart= to"
echo "    replace the default command line. Example:"
echo "  "
echo "    [Service]"
echo "    ExecStart="
echo "    ExecStart=/usr/bin/lorica --data-dir /var/lib/lorica \\"
echo "      --workers 6 \\"
echo "      --management-port 9443 \\"
echo "      --http-port 8080 \\"
echo "      --https-port 8443 \\"
echo "      --log-level info"
echo "  "
echo "  Available flags:"
echo "    --workers N          worker processes (0 = single-process)"
echo "    --management-port N  dashboard port (default: 9443)"
echo "    --http-port N        HTTP proxy port (default: 8080)"
echo "    --https-port N       HTTPS proxy port (default: 8443)"
echo "    --cluster-listen H:P cluster plane listener (opt-in,"
echo "                         disabled by default; 9444 by convention,"
echo "                         see docs/cluster.md before opening it)"
echo "    --log-level LEVEL    trace|debug|info|warn|error"
echo "  "
echo "  Encryption key: /var/lib/lorica/encryption.key"
echo "    BACK UP THIS FILE - losing it makes encrypted"
echo "    data (cert keys, SMTP passwords) unrecoverable."
echo "    Rotate with: lorica rotate-key --new-key-file /path/to/new.key"
echo "  ================================================"
echo ""
EOF
chmod 755 "$PKG_DIR/DEBIAN/postinst"

# Pre-removal script. Stopped on every path out of this version, disabled
# only when the package is removed: an upgrade leaves the operator's
# enablement alone, and records whether the service was running so the
# next version's postinst restarts it only then.
cat > "$PKG_DIR/DEBIAN/prerm" << 'EOF'
#!/bin/sh
set -e
if [ "$1" = "upgrade" ]; then
    if [ "$(systemctl is-active lorica.service 2>/dev/null || true)" = active ]; then
        printf 'active\n' > /run/lorica-package.state 2>/dev/null || true
    else
        printf 'inactive\n' > /run/lorica-package.state 2>/dev/null || true
    fi
fi
systemctl stop lorica.service 2>/dev/null || true
if [ "$1" = "remove" ]; then
    systemctl disable lorica.service 2>/dev/null || true
fi
EOF
chmod 755 "$PKG_DIR/DEBIAN/prerm"

# Post-removal script. The daemon reload belongs to a removal: on an
# upgrade the new postinst reloads, after its ownership repair has run,
# and not at all on a host that repair left stopped.
cat > "$PKG_DIR/DEBIAN/postrm" << 'EOF'
#!/bin/sh
set -e
if [ "$1" = "purge" ]; then
    rm -rf /var/lib/lorica
    userdel lorica 2>/dev/null || true
fi
if { [ "$1" = "remove" ] || [ "$1" = "purge" ]; } && [ -d /run/systemd/system ]; then
    systemctl daemon-reload
fi
EOF
chmod 755 "$PKG_DIR/DEBIAN/postrm"

# No conffiles - the systemd service file is owned by the package and
# replaced freely on upgrade. Users customize via drop-in overrides:
#   systemctl edit lorica
# This creates /etc/systemd/system/lorica.service.d/override.conf

# Modes are set here rather than inherited from the builder's umask.
find "$PKG_DIR" -type d -exec chmod 755 {} +
chmod 644 "$PKG_DIR/DEBIAN/control"

# Build the package. --root-owner-group records every entry as root:root
# whatever account runs this: CI builds as the unprivileged `runner` user,
# and without it dpkg-deb wrote that account into the package, which dpkg
# then applied on install (the advisory fixed in 1.9.0).
dpkg-deb --root-owner-group --build "$PKG_DIR"

echo "Package built: dist/${PKG_NAME}.deb"
ls -lh "dist/${PKG_NAME}.deb"
