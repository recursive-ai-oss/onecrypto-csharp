#!/usr/bin/env bash
# Builds our tool and runs the key-management matrix against each sop-speaking oracle installed under the oracle directory.
# Usage: tools/oracles/run-keys-matrices.sh <work dir> [oracle names: sqop gosop pgpjs]
set -u
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
W=${1:?work dir}; shift
ORACLES=${ONECRYPTO_ORACLES:-$HOME/onecrypto/oracles}
export PATH=$HOME/dotnet10:$HOME/onecrypto/tools/node/bin:$PATH DOTNET_ROOT=$HOME/dotnet10 ONECRYPTO_ARTIFACTS=${ONECRYPTO_ARTIFACTS:-$W/artifacts}
export OPENPGP_JS_DIR=${OPENPGP_JS_DIR:-$ORACLES/openpgpjs-6.3.2}
mkdir -p "$W"
(cd "$root" && dotnet build -c Release src/OneCrypto.Cli -v quiet -clp:NoSummary) || exit 2
dll=$(find "$ONECRYPTO_ARTIFACTS" -name onecrypto.dll -path '*release*' | head -1)
[ -n "$dll" ] || { echo "onecrypto.dll not found under $ONECRYPTO_ARTIFACTS" >&2; exit 2; }
OURS="dotnet $dll sop"
names=${*:-sqop gosop pgpjs}
rc=0
for n in $names; do
  case $n in
    sqop) other="$ORACLES/sequoia-sop-nettle/bin/sqop" ;;
    gosop) other="$ORACLES/gosop-v1.1.0/gosop" ;;
    pgpjs) other="node $root/tools/oracles/pgpjs6/sop.mjs" ;;
    *) echo "unknown oracle $n" >&2; continue ;;
  esac
  echo "=== $n: $other"
  "$root/tools/oracles/sop-keys-matrix.sh" "$OURS" "$other" "$W/$n" > "$W/$n.log" 2>&1 || rc=1
  tail -1 "$W/$n.log"
done
exit $rc
