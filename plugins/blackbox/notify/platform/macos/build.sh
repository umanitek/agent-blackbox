#!/usr/bin/env bash
# Builds Blackbox's macOS notifier: Blackbox.app (ad-hoc signed) and blackbox-notify-darwin.zip.
#
#   plugins/blackbox/notify/platform/macos/build.sh <output folder>
#
# Prints "sha256 <hex>  blackbox-notify-darwin.zip" — the line a release manifest carries and what
# `blackbox notifications setup --from <zip> --sha256 <hex>` checks. Needs Xcode's command line
# tools (swiftc, codesign); a person's Mac does not: the installer places the built archive.
set -euo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
out="${1:?usage: build.sh <output folder>}"
mkdir -p "$out"
app="$out/Blackbox.app"
rm -rf "$app" "$out/blackbox-notify-darwin.zip"
mkdir -p "$app/Contents/MacOS" "$app/Contents/Resources"
cp "$here/Info.plist" "$app/Contents/Info.plist"
for arch in arm64 x86_64; do
    swiftc -O -target "$arch-apple-macos12.0" -o "$out/blackbox-notify-$arch" "$here/notifier.swift"
done
lipo -create -output "$app/Contents/MacOS/blackbox-notify" "$out/blackbox-notify-arm64" "$out/blackbox-notify-x86_64"
rm -f "$out/blackbox-notify-arm64" "$out/blackbox-notify-x86_64"
# The icon is drawn from the dashboard's own logo when the system tools can do it; without one
# macOS shows its generic app icon (the name is still Blackbox).
logo="$here/../../../dashboard/assets/blackbox-logo.svg"
if [ -f "$logo" ] && command -v qlmanage >/dev/null && command -v iconutil >/dev/null; then
    work="$(mktemp -d)"
    if qlmanage -t -s 1024 -o "$work" "$logo" >/dev/null 2>&1 && [ -f "$work/blackbox-logo.svg.png" ]; then
        mkdir "$work/Blackbox.iconset"
        for size in 16 32 128 256 512; do
            sips -z "$size" "$size" "$work/blackbox-logo.svg.png" --out "$work/Blackbox.iconset/icon_${size}x${size}.png" >/dev/null
            sips -z "$((size * 2))" "$((size * 2))" "$work/blackbox-logo.svg.png" --out "$work/Blackbox.iconset/icon_${size}x${size}@2x.png" >/dev/null
        done
        iconutil -c icns -o "$app/Contents/Resources/Blackbox.icns" "$work/Blackbox.iconset" || true
    fi
    rm -rf "$work"
fi
codesign --force --sign - --identifier ai.umanitek.blackbox.notifier "$app"
(cd "$out" && ditto -c -k --keepParent Blackbox.app blackbox-notify-darwin.zip)
printf 'sha256 %s  blackbox-notify-darwin.zip\n' "$(shasum -a 256 "$out/blackbox-notify-darwin.zip" | awk '{print $1}')"
