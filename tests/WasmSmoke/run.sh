#!/usr/bin/env bash
# Publish the browser-wasm smoke app and run it under Node.
#
#   tests/WasmSmoke/run.sh <output dir>
#
# Needs the wasm-tools workload (dotnet workload install wasm-tools) and Node 20 or newer.
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
out="${1:?usage: run.sh <output dir>}"
dotnet publish "$here/OneCrypto.WasmSmoke.csproj" -c Release -v quiet -clp:NoSummary -o "$out"
cp "$here/main.mjs" "$out/wwwroot/main.mjs"
(cd "$out/wwwroot" && node main.mjs) | tee "$out/smoke.log"
"$here/../../tools/check-availability.sh" "$out/smoke.log"
