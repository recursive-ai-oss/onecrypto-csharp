#!/usr/bin/env bash
# Installs the pinned Chrome for Testing headless shell (linux64) under a directory of the caller's choosing, for the
# browser suite (tests/BrowserSuite). Nothing is installed system-wide and nothing is committed.
#
#   tools/fetch-chrome-headless.sh <install dir>
#
# Prints the path of the executable on the last line. The archive's SHA-256 is checked against the value pinned below:
# the download host publishes no checksum of its own (only MD5/CRC32C object metadata), so the pin is the digest we
# recorded when we chose the version. Move both together.
set -euo pipefail
version="156.0.8078.80"
sha256="${CHROME_HEADLESS_SHA256:-547dcd374e02961bf998f6046a267644f8502225c36bb78ca307dab32a0b3eb4}"
dest="${1:?usage: fetch-chrome-headless.sh <install dir>}"
url="https://storage.googleapis.com/chrome-for-testing-public/${version}/linux64/chrome-headless-shell-linux64.zip"
bin="$dest/chrome-headless-shell-$version/chrome-headless-shell-linux64/chrome-headless-shell"
if [ -x "$bin" ]; then echo "$bin"; exit 0; fi
mkdir -p "$dest/chrome-headless-shell-$version"
zip="$dest/chrome-headless-shell-$version.zip"
curl -fsSL --retry 3 -o "$zip" "$url"
actual=$(sha256sum "$zip" | cut -d' ' -f1)
[ "$actual" = "$sha256" ] || { echo "chrome-headless-shell digest mismatch: $actual" >&2; rm -f "$zip"; exit 1; }
if command -v unzip >/dev/null; then unzip -q -o "$zip" -d "$dest/chrome-headless-shell-$version"
else python3 -c 'import sys,zipfile; zipfile.ZipFile(sys.argv[1]).extractall(sys.argv[2])' "$zip" "$dest/chrome-headless-shell-$version"; fi
chmod +x "$bin"
rm -f "$zip"
echo "$bin"
