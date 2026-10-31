#!/usr/bin/env bash
# Fetches the Wycheproof test vectors at the pinned commit into $ONECRYPTO_VECTORS/wycheproof (default ~/onecrypto/vectors).
# Only the JSON files under testvectors_v1/ are used. Nothing is committed to the repository.
set -euo pipefail
COMMIT=d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9
SHA256=${WYCHEPROOF_SHA256:-88dcda078c6ff643cf95c676e781c595f76e768d66ad85c01e1704f26d062ddc}
dest=${ONECRYPTO_VECTORS:-$HOME/onecrypto/vectors}/wycheproof
if [ -f "$dest/.commit" ] && [ "$(cat "$dest/.commit")" = "$COMMIT" ]; then
  echo "wycheproof $COMMIT already present in $dest"
  exit 0
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL -o "$tmp/w.tar.gz" "https://github.com/C2SP/wycheproof/archive/$COMMIT.tar.gz"
actual=$(sha256sum "$tmp/w.tar.gz" | cut -d' ' -f1)
echo "tarball sha256 $actual"
if [ -n "$SHA256" ] && [ "$actual" != "$SHA256" ]; then
  echo "checksum mismatch (expected $SHA256)" >&2
  exit 1
fi
mkdir -p "$dest"
tar -xzf "$tmp/w.tar.gz" -C "$tmp"
rm -rf "$dest/testvectors_v1"
cp -r "$tmp/wycheproof-$COMMIT/testvectors_v1" "$dest/testvectors_v1"
echo "$COMMIT" > "$dest/.commit"
echo "fetched into $dest"
