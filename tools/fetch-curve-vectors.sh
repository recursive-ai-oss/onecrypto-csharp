#!/usr/bin/env bash
# Fetches the published test vectors the Curve25519/Curve448 tests use, at pinned commits, into a cache outside the checkout.
# Only the JSON vector files are fetched; nothing here is committed.
#   ONECRYPTO_VECTORS  target directory (default: ~/onecrypto/vectors)
set -euo pipefail
DEST="${ONECRYPTO_VECTORS:-$HOME/onecrypto/vectors}"
WYCHEPROOF=d17cc89fa5c8f4f4d378b5385ebf75da5d0926c9
CCTV=50a8ecf2a220f4c8bdc4f085789b8e85c26829e7

fetch() { # url dest
  [ -s "$2" ] && return 0
  mkdir -p "$(dirname "$2")"
  curl -fsSL --retry 3 -o "$2.part" "$1" && mv "$2.part" "$2"
}

for f in ed25519_test ed448_test x25519_test x448_test; do
  fetch "https://raw.githubusercontent.com/C2SP/wycheproof/$WYCHEPROOF/testvectors_v1/$f.json" "$DEST/wycheproof/testvectors_v1/$f.json"
done
fetch "https://raw.githubusercontent.com/C2SP/CCTV/$CCTV/ed25519/ed25519vectors.json" "$DEST/CCTV/ed25519/ed25519vectors.json"
sha256sum "$DEST"/wycheproof/testvectors_v1/{ed25519,ed448,x25519,x448}_test.json "$DEST/CCTV/ed25519/ed25519vectors.json"
