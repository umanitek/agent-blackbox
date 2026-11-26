#!/usr/bin/env bash
# Builds the notifier app's icon (Blackbox.icns) from the dashboard's Blackbox mark — the same
# artwork as the dashboard's tab icon (dashboard/assets/blackbox-mark.svg); no artwork of its own.
#
#   plugins/blackbox/notify/platform/macos/icon.sh <output .icns>
#
# Needs Xcode's command line tools (swiftc) and the system's sips and iconutil. build.sh runs it.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:?usage: icon.sh <output .icns>}"
mark="$here/../../../dashboard/assets/blackbox-mark.svg"
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
swiftc -O -o "$work/icon" "$here/icon.swift"
"$work/icon" "$mark" "$work/mark.png" 1024
mkdir "$work/Blackbox.iconset"
for size in 16 32 128 256 512; do
    sips -z "$size" "$size" "$work/mark.png" --out "$work/Blackbox.iconset/icon_${size}x${size}.png" >/dev/null
    sips -z "$((size * 2))" "$((size * 2))" "$work/mark.png" --out "$work/Blackbox.iconset/icon_${size}x${size}@2x.png" >/dev/null
done
iconutil -c icns -o "$out" "$work/Blackbox.iconset"
