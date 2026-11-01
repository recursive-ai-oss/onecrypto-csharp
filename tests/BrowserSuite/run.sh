#!/usr/bin/env bash
# Builds the browser-wasm suite and runs it in a headless Chromium, under Node and natively, then compares the three.
#
#   tests/BrowserSuite/run.sh <output dir> [areas]
#
# Needs: the wasm-tools workload, Node 22 or newer, python3. Environment:
#   ONECRYPTO_BROWSER        path of a Chrome headless shell; default: installed by tools/fetch-chrome-headless.sh into
#                            $ONECRYPTO_BROWSER_CACHE (default <output dir>/browser)
#   ONECRYPTO_VECTORS        folder holding wycheproof/ and x509-limbo/ (the fetch scripts' layout); without it only the committed
#                            fixtures run, which is what hosted CI does
#   ONECRYPTO_LIMBO          path of limbo.json when it is not under ONECRYPTO_VECTORS
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
out="${1:?usage: run.sh <output dir> [areas]}"
areas="${2:-all}"
mkdir -p "$out"
out="$(cd "$out" && pwd)"

data_args=()
if [ -n "${ONECRYPTO_VECTORS:-}" ]; then
  data_args+=(--vectors "$ONECRYPTO_VECTORS")
  limbo="${ONECRYPTO_LIMBO:-$ONECRYPTO_VECTORS/x509-limbo/limbo.json}"
  [ -f "$limbo" ] && data_args+=(--limbo "$limbo")
fi
python3 "$root/tools/gen-browser-data.py" "$out/suite-data.json" "${data_args[@]}"

browser="${ONECRYPTO_BROWSER:-$("$root/tools/fetch-chrome-headless.sh" "${ONECRYPTO_BROWSER_CACHE:-$out/browser}" | tail -1)}"
echo "browser: $("$browser" --version)"

dotnet publish "$here/OneCrypto.BrowserSuite.csproj" -c Release -v quiet -clp:NoSummary -p:SuiteData="$out/suite-data.json" -o "$out/app"
cp "$here/index.html" "$here/browser-main.js" "$here/node-main.mjs" "$out/app/wwwroot/"
dotnet build "$root/tests/BrowserSuiteNative/OneCrypto.BrowserSuiteNative.csproj" -c Release -v quiet -clp:NoSummary -p:SuiteData="$out/suite-data.json" -o "$out/native"

status=0
dotnet "$out/native/OneCrypto.BrowserSuiteNative.dll" "$areas" > "$out/native.out" || status=1
dotnet "$out/native/OneCrypto.BrowserSuiteNative.dll" "$areas" force-fallbacks > "$out/native-forced.out" || status=1
(cd "$out/app/wwwroot" && node node-main.mjs "$areas" > "$out/node.out" 2> "$out/node.err") || status=1
areas_query=""
[ "$areas" != all ] && areas_query="$areas"
node "$here/serve-and-drive.mjs" "$out/app/wwwroot" "$browser" "$out/chromium.out" $areas_query | tee "$out/chromium.log" || status=1

if [ "$areas" = all ] || [[ ",$areas," == *,platform,* ]]; then
  "$root/tools/check-availability.sh" "$out/chromium.out" || status=1
  "$root/tools/check-availability.sh" "$out/node.out" || status=1
fi
python3 "$here/compare.py" "$out/report.md" "$out/chromium.out" "$out/node.out" "$out/native.out" "$out/native-forced.out" || status=1
echo "report: $out/report.md"
exit $status
