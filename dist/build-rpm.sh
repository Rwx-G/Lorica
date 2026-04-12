#!/usr/bin/env bash
# Build an .rpm package for Lorica.
# Usage: bash dist/build-rpm.sh [binary_path]
#   binary_path defaults to ./lorica (current directory)
#   Requires: rpm-build

set -euo pipefail
cd "$(dirname "$0")/.."

BINARY="${1:-./lorica}"
VERSION=$(grep '^Version:' dist/rpm/lorica.spec | awk '{print $2}' | tr -d '\r')
RPMTOP="dist/.rpmbuild"

echo "Building .rpm package: lorica ${VERSION} (x86_64)"

# Verify rpmbuild is available
if ! command -v rpmbuild &>/dev/null; then
    echo "ERROR: rpmbuild not found. Install rpm-build package."
    exit 1
fi

# Clean and create rpmbuild tree
rm -rf "$RPMTOP"
mkdir -p "$RPMTOP"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

# Copy binary and service file to SOURCES
cp "$BINARY" "$RPMTOP/SOURCES/lorica"
mkdir -p "$RPMTOP/SOURCES/dist"
cp dist/lorica.service "$RPMTOP/SOURCES/dist/lorica.service"

# Copy LICENSE and NOTICE (Apache-2.0 section 4(d) compliance)
cp LICENSE "$RPMTOP/SOURCES/LICENSE"
cp NOTICE "$RPMTOP/SOURCES/NOTICE"

# Copy spec with current version
cp dist/rpm/lorica.spec "$RPMTOP/SPECS/lorica.spec"

# Build RPM
rpmbuild --define "_topdir $(pwd)/$RPMTOP" \
    --define "_sourcedir $(pwd)/$RPMTOP/SOURCES" \
    -bb "$RPMTOP/SPECS/lorica.spec"

# Copy result to dist/
cp "$RPMTOP/RPMS/x86_64/"*.rpm dist/ 2>/dev/null || true
rm -rf "$RPMTOP"

echo "Package built:"
ls -lh dist/*.rpm 2>/dev/null
