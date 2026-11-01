#!/usr/bin/env bash
# Runs the whole key-management oracle set on a worker: the sop matrices (sqop, gosop, OpenPGP.js), GnuPG (GPG env var) and RNP.
# Usage: tools/oracles/run-keys-all.sh <work dir> [sqop gosop pgpjs]   (needs ~/onecrypto/oracles filled by the oracle scripts)
set -u
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
W=${1:?work dir}; shift
export PATH=$HOME/dotnet10:$HOME/onecrypto/tools/node/bin:$PATH DOTNET_ROOT=$HOME/dotnet10 ONECRYPTO_ARTIFACTS=$W/artifacts
O=$HOME/onecrypto/oracles
mkdir -p "$W"
# OpenSSL 3.5 gives ML-DSA/ML-KEM to the platform layer, so the PQC profiles can run
export LD_LIBRARY_PATH=$O/openssl-3.5.9/lib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
# with names: only those sop matrices; without: GnuPG 2.5.24 and RNP
if [ $# -gt 0 ]; then "$root/tools/oracles/run-keys-matrices.sh" "$W/m" "$@"; exit $?; fi
"$root/tools/oracles/run-keys-matrices.sh" "$W/m" build-only >/dev/null 2>&1
dll=$(find "$W/artifacts" -path '*/bin/OneCrypto.Cli/release/onecrypto.dll' | head -1)
echo "=== gpg 2.5.24"; GPG=$O/gnupg-2.5.24/bin/gpg "$root/tools/oracles/gpg-keys.sh" "dotnet $dll" "$W/g" > "$W/gpg.log" 2>&1; tail -1 "$W/gpg.log"
echo "=== rnp"; "$root/tools/oracles/rnp-keys.sh" "dotnet $dll" "$W/r" > "$W/rnp.log" 2>&1; tail -1 "$W/rnp.log"
