#!/usr/bin/env bash
# Builds the BetterTLS test-suite generator at the pinned commit with the Go toolchain, runs its documented `export-tests` command and
# writes the two suites to $ONECRYPTO_VECTORS/bettertls/{nameconstraints,pathbuilding}.json (default ~/onecrypto/vectors).
# The generator is only run; its source is not read. BetterTLS is Apache-2.0 (Netflix); nothing is committed to the repository.
# A fixed root CA file keeps the exported certificates identical between runs of this script.
set -euo pipefail
COMMIT=bc5adea19ed8dc0d14d8be265ce48ee4605047cf
V=${ONECRYPTO_VECTORS:-$HOME/onecrypto/vectors}
src=$V/bettertls-src
out=$V/bettertls
mkdir -p "$src" "$out"
if [ ! -x "$src/bettertls" ]; then
  [ -f "$src/src.tgz" ] || curl -fsSL -o "$src/src.tgz" "https://github.com/Netflix/bettertls/archive/$COMMIT.tar.gz"
  sha256sum "$src/src.tgz"
  tar -xzf "$src/src.tgz" -C "$src"
  (cd "$src/bettertls-$COMMIT" && go build -o "$src/bettertls" ./test-suites/cmd/bettertls)
fi
for suite in nameconstraints pathbuilding; do
  "$src/bettertls" export-tests -suite "$suite" -rootCa "$out/root-ca.pem" -out "$out/$suite.json"
done
sha256sum "$out"/*.json
