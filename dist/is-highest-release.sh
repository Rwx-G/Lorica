#!/usr/bin/env bash
# Decide whether a release tag may replace the package repositories.
# Usage: <published tag names, one per line> | bash dist/is-highest-release.sh <tag>
#   exit 0  the tag is at least as high as every published release: publish
#   exit 1  it is lower than one of them, or a pre-release: leave the site
#   exit 2  usage error
#
# The repositories hold the highest release, so a fix on an older line
# never replaces them. A tag carrying `-` (`v1.11.0-rc.1`) is a pre-release:
# it never publishes, and one in the list is ignored, as `sort -V` ranks
# `1.11.0-rc.1` above `1.11.0`.

set -euo pipefail

if [ "$#" -ne 1 ]; then
    sed -n '3,6p' "$0" >&2
    exit 2
fi

tag="$1"
version="${tag#v}"

case "$version" in
    *-*)
        echo "$tag is a pre-release: the package repositories are left as they are"
        exit 1
        ;;
esac

highest=$(awk '{ sub(/^v/, "") } $0 != "" && $0 !~ /-/' | sort -V | tail -n 1)

if [ -z "$highest" ] || [ "$(printf '%s\n%s\n' "$version" "$highest" | sort -V | tail -n 1)" = "$version" ]; then
    echo "$tag is the highest release: the package repositories are replaced"
    exit 0
fi
echo "$tag is lower than the published v$highest: the package repositories are left as they are"
exit 1
