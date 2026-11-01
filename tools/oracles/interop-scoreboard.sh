#!/usr/bin/env bash
# Runs the OpenPGP interoperability test suite against our `sop` and every installed oracle driver, writing a JSON report and an
# HTML report per run, then a one-line-per-driver summary. Drivers that are not installed are listed as missing.
#   tools/oracles/interop-scoreboard.sh <onecrypto.dll-or-tool-directory> <output-dir> [--retain-tests REGEX]
# The suite is a black box: it is executed, its results are read, nothing of it is kept in the repository.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
export PATH=$HOME/.cargo/bin:$PATH
DLL=${1:?usage: interop-scoreboard.sh <onecrypto.dll> <output-dir> [suite args]}; OUT=${2:?}; shift 2
SUITE=$(ls -d "$ORACLES"/interop-suite-*/bin/openpgp-interoperability-test-suite | head -1)
mkdir -p "$OUT"; OUT=$(cd "$OUT" && pwd)
wrap=$OUT/onecrypto-sop; printf '#!/bin/sh\nexec dotnet "%s" sop "$@"\n' "$(cd "$(dirname "$DLL")" && pwd)/$(basename "$DLL")" > "$wrap"; chmod +x "$wrap"
declare -A DRIVERS=(
  [onecrypto]="$wrap"
  [sqop-0.38.0]="$ORACLES/sequoia-sop-nettle/bin/sqop"
  [gosop-1.1.0]="$ORACLES/gosop-v1.1.0/gosop"
  [sop-openpgp-js-0.1.1]="$ORACLES/pgpjs-sop-0.1.1/node_modules/.bin/sop-openpgp"
)
entries=""; missing=""
for id in "${!DRIVERS[@]}"; do
  p=${DRIVERS[$id]}
  if [ -x "$p" ]; then entries="$entries{\"path\":\"$p\",\"id\":\"$id\",\"env\":{\"PATH\":\"$HOME/onecrypto/tools/node/bin:$HOME/dotnet10:/usr/bin:/bin\",\"DOTNET_ROOT\":\"$HOME/dotnet10\",\"DOTNET_NOLOGO\":\"1\"}},"; else missing="$missing $id"; fi
done
cfg=$OUT/config.json
printf '{"drivers":[%s],"rlimits":{"CPU":60,"DATA":4294967296}}\n' "${entries%,}" > "$cfg"
[ -n "$missing" ] && echo "missing drivers:$missing" | tee "$OUT/missing.txt"
"$SUITE" --config "$cfg" --json-out "$OUT/results.json" --html-out "$OUT/results.html" "$@" 2>&1 | tail -5
ls -l "$OUT/results.json"
