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
# The icon is the dashboard's Blackbox mark (icon.sh); without the tools for it macOS shows its
# generic app icon (the name is still Blackbox).
"$here/icon.sh" "$app/Contents/Resources/Blackbox.icns" || echo "note: the icon could not be built; macOS shows its generic one" >&2
codesign --force --sign - --identifier ai.umanitek.blackbox.notifier "$app"
(cd "$out" && ditto -c -k --keepParent Blackbox.app blackbox-notify-darwin.zip)
printf 'sha256 %s  blackbox-notify-darwin.zip\n' "$(shasum -a 256 "$out/blackbox-notify-darwin.zip" | awk '{print $1}')"
