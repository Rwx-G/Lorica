#!/usr/bin/env bash
# Build a .deb package for Lorica.
# Usage: bash dist/build-deb.sh [binary_path]
#   binary_path defaults to ./lorica (current directory)

set -euo pipefail
cd "$(dirname "$0")/.."

BINARY="${1:-./lorica}"
VERSION=$(grep '^version' lorica/Cargo.toml | head -1 | sed 's/.*"\(.*\)"/\1/')
ARCH="amd64"
PKG_NAME="lorica_${VERSION}_${ARCH}"
PKG_DIR="dist/${PKG_NAME}"

echo "Building .deb package: lorica ${VERSION} (${ARCH})"

# Create package structure
rm -rf "$PKG_DIR"
mkdir -p "$PKG_DIR/DEBIAN"
mkdir -p "$PKG_DIR/usr/bin"
mkdir -p "$PKG_DIR/lib/systemd/system"
mkdir -p "$PKG_DIR/var/lib/lorica"

# Copy binary
cp "$BINARY" "$PKG_DIR/usr/bin/lorica"
chmod 755 "$PKG_DIR/usr/bin/lorica"

# Copy systemd service
cp dist/lorica.service "$PKG_DIR/lib/systemd/system/"

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
Homepage: https://github.com/Rwx-G/Lorica
Depends: ca-certificates
EOF

# Post-install script
cat > "$PKG_DIR/DEBIAN/postinst" << 'EOF'
#!/bin/sh
set -e

# Create system user
if ! id -u lorica >/dev/null 2>&1; then
    useradd -r -s /bin/false -d /var/lib/lorica lorica
fi

# Set permissions
chown -R lorica:lorica /var/lib/lorica
chmod 750 /var/lib/lorica

# Enable and (re)start service
systemctl daemon-reload
systemctl enable lorica.service
systemctl restart lorica.service 2>/dev/null || systemctl start lorica.service

echo ""
echo "  ================================================"
echo "  Lorica installed successfully!"
echo "  "
echo "  Dashboard: https://localhost:9443"
echo "  "
echo "  The admin password will be printed in the journal:"
echo "    journalctl -u lorica -n 20"
echo "  "
echo "  Customize with: systemctl edit lorica"
echo "    (e.g. add --workers 6 via ExecStart override)"
echo "  ================================================"
echo ""
EOF
chmod 755 "$PKG_DIR/DEBIAN/postinst"

# Pre-removal script
cat > "$PKG_DIR/DEBIAN/prerm" << 'EOF'
#!/bin/sh
set -e
systemctl stop lorica.service 2>/dev/null || true
systemctl disable lorica.service 2>/dev/null || true
EOF
chmod 755 "$PKG_DIR/DEBIAN/prerm"

# Post-removal (purge) script
cat > "$PKG_DIR/DEBIAN/postrm" << 'EOF'
#!/bin/sh
set -e
if [ "$1" = "purge" ]; then
    rm -rf /var/lib/lorica
    userdel lorica 2>/dev/null || true
fi
systemctl daemon-reload
EOF
chmod 755 "$PKG_DIR/DEBIAN/postrm"

# No conffiles - the systemd service file is owned by the package and
# replaced freely on upgrade. Users customize via drop-in overrides:
#   systemctl edit lorica
# This creates /etc/systemd/system/lorica.service.d/override.conf

# Build the package
dpkg-deb --build "$PKG_DIR"

echo "Package built: dist/${PKG_NAME}.deb"
ls -lh "dist/${PKG_NAME}.deb"
