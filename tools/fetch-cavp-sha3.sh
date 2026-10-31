#!/usr/bin/env bash
# Fetches the NIST CAVP SHA-3 and SHAKE byte-oriented test vectors (FIPS 202) into $ONECRYPTO_VECTORS/cavp-sha3 (default ~/onecrypto/vectors).
# NIST publishes them as US government work; nothing is committed to the repository.
set -euo pipefail
base=https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/sha3
dest=${ONECRYPTO_VECTORS:-$HOME/onecrypto/vectors}/cavp-sha3
if [ -f "$dest/.done" ]; then
  echo "CAVP SHA-3 vectors already present in $dest"
  exit 0
fi
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
fetch() { # name sha256
  curl -fsSL -o "$tmp/$1.zip" "$base/$1.zip"
  actual=$(sha256sum "$tmp/$1.zip" | cut -d' ' -f1)
  if [ "$actual" != "$2" ]; then echo "checksum mismatch for $1: $actual" >&2; exit 1; fi
  mkdir -p "$dest"
  unzip -o -q "$tmp/$1.zip" -d "$dest"
}
fetch sha-3bytetestvectors cd07701af2e47f5cc889d642528b4bf11f8b6eb55797c7307a96828ed8d8fc8c
fetch shakebytetestvectors debfebc3157b3ceea002b84ca38476420389a3bf7e97dc5f53ea4689a16de4c7
touch "$dest/.done"
echo "fetched into $dest"
