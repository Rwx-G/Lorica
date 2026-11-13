#!/usr/bin/env bash
# Build the signed apt and dnf repositories published on GitHub Pages.
# Usage: bash dist/build-package-repo.sh <out-dir> <base-url> <key-id> <public-key> <deb> <rpm>
#   out-dir     the site root; created if missing, refused if not empty
#   base-url    where out-dir is served, e.g. https://rwx-g.github.io/Lorica;
#               written into the client files lorica.sources and lorica.repo
#   key-id      the gpg key that signs the index metadata
#   public-key  that key's public half, copied as is to the site root as
#               lorica-signing-key.asc (docs/lorica-signing-key.asc for a release)
#   deb, rpm    the packages; the .rpm must already carry its own signature,
#               since the client file turns on gpgcheck
#   GPG_PASSPHRASE_FILE  optional, the file holding the key's passphrase
#   Requires: apt-ftparchive (apt-utils), createrepo_c, gpg, gzip
#
# The site holds these two packages and nothing else: each release replaces
# it whole. The release job and the CI repository test both run this
# script, so the layout and client files tested are the ones that ship.

set -euo pipefail

if [ "$#" -ne 6 ]; then
    sed -n '3,13p' "$0" >&2
    exit 2
fi

OUT="$1"
BASE_URL="${2%/}"
KEY_ID="$3"
PUBLIC_KEY="$4"
DEB="$5"
RPM="$6"

for input in "$PUBLIC_KEY" "$DEB" "$RPM"; do
    if [ ! -f "$input" ]; then
        echo "ERROR: $input is not a file" >&2
        exit 1
    fi
done

mkdir -p "$OUT"
if [ -n "$(ls -A "$OUT")" ]; then
    echo "ERROR: $OUT is not empty; the site is built from nothing" >&2
    exit 1
fi
OUT=$(cd "$OUT" && pwd)

gpg_sign=(gpg --batch --yes --local-user "$KEY_ID" --digest-algo SHA512)
if [ -n "${GPG_PASSPHRASE_FILE:-}" ]; then
    gpg_sign+=(--pinentry-mode loopback --passphrase-file "$GPG_PASSPHRASE_FILE")
fi

cp "$PUBLIC_KEY" "$OUT/lorica-signing-key.asc"

# apt: suite `stable`, component `main`, one architecture.
apt_root="$OUT/apt"
suite_dir="$apt_root/dists/stable"
mkdir -p "$apt_root/pool/main/l/lorica" "$suite_dir/main/binary-amd64"
cp "$DEB" "$apt_root/pool/main/l/lorica/"
(cd "$apt_root" && apt-ftparchive packages pool) > "$suite_dir/main/binary-amd64/Packages"
gzip -9 -n -k "$suite_dir/main/binary-amd64/Packages"

# Written outside the suite directory first: apt-ftparchive hashes every
# file it finds there, a half-written Release included. No Valid-Until:
# the site stays as it is until the next release, however long that is.
release_tmp=$(mktemp)
(cd "$suite_dir" && apt-ftparchive \
    -o APT::FTPArchive::MD5=false \
    -o APT::FTPArchive::SHA1=false \
    -o APT::FTPArchive::Release::Origin=Lorica \
    -o APT::FTPArchive::Release::Label=Lorica \
    -o APT::FTPArchive::Release::Suite=stable \
    -o APT::FTPArchive::Release::Codename=stable \
    -o APT::FTPArchive::Release::Architectures=amd64 \
    -o APT::FTPArchive::Release::Components=main \
    -o "APT::FTPArchive::Release::Description=Lorica, latest release only" \
    release .) > "$release_tmp"
mv "$release_tmp" "$suite_dir/Release"
chmod 644 "$suite_dir/Release"
"${gpg_sign[@]}" --clearsign --output "$suite_dir/InRelease" "$suite_dir/Release"
"${gpg_sign[@]}" --armor --detach-sign --output "$suite_dir/Release.gpg" "$suite_dir/Release"

# Armored keyrings in Signed-By are read from apt 2.4 (Ubuntu 22.04), the
# oldest apt on a system with the glibc the binaries need.
cat > "$apt_root/lorica.sources" << EOF
Types: deb
URIs: ${BASE_URL}/apt
Suites: stable
Components: main
Architectures: amd64
Signed-By: /etc/apt/keyrings/lorica.asc
EOF

# dnf: gzip metadata and no sqlite databases, which every dnf supported
# reads; repomd.xml signed for repo_gpgcheck, the package for gpgcheck.
rpm_root="$OUT/rpm"
mkdir -p "$rpm_root"
cp "$RPM" "$rpm_root/"
createrepo_c --no-database --general-compress-type=gz "$rpm_root"
"${gpg_sign[@]}" --armor --detach-sign --output "$rpm_root/repodata/repomd.xml.asc" "$rpm_root/repodata/repomd.xml"

# The key is a local file the operator placed and checked once: a key URL
# on this site would let whoever controls the site swap the key with the
# packages, and `dnf -y` imports whatever key the URL serves.
cat > "$rpm_root/lorica.repo" << EOF
[lorica]
name=Lorica
baseurl=${BASE_URL}/rpm
enabled=1
gpgcheck=1
repo_gpgcheck=1
gpgkey=file:///etc/pki/rpm-gpg/RPM-GPG-KEY-lorica
EOF

echo "Package repository built in $OUT for $BASE_URL:"
(cd "$OUT" && find . -type f | sort)
