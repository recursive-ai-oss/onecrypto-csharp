#!/usr/bin/env bash
# Fetches NIST's PKITS test data and document into $ONECRYPTO_VECTORS/pkits (default ~/onecrypto/vectors) and extracts the zip.
# NIST PKI Testing (https://csrc.nist.gov/projects/pki-testing): a US government work. Nothing is committed to the repository.
set -euo pipefail
BASE=https://csrc.nist.gov/CSRC/media/Projects/PKI-Testing/documents
ZIP_SHA256=592f66030d2eff80fced7ad022e197d96b7ee4ccce7da9df9c9b2007b1665665
PDF_SHA256=506913f4b727704ee1b52b17aa472dc6fbcf01e41e7ad88ba505f29c1a74d9ea
dest=${ONECRYPTO_VECTORS:-$HOME/onecrypto/vectors}/pkits
mkdir -p "$dest"
for pair in "PKITS_data.zip $ZIP_SHA256" "PKITS.pdf $PDF_SHA256"; do
  set -- $pair
  [ -f "$dest/$1" ] || curl -fsSL -o "$dest/$1" "$BASE/$1"
  actual=$(sha256sum "$dest/$1" | cut -d' ' -f1)
  [ "$actual" = "$2" ] || { echo "checksum mismatch for $1: $actual" >&2; exit 1; }
done
[ -d "$dest/data/certs" ] || { mkdir -p "$dest/data"; unzip -q -o "$dest/PKITS_data.zip" -d "$dest/data"; }
echo "PKITS data in $dest/data"
