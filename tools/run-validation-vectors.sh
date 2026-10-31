#!/usr/bin/env bash
# Runs the x509-limbo corpus through the path validator and writes one line per testcase to $OUT (default: ./limbo.tsv).
# Needs tools/fetch-x509-limbo.sh to have been run. Usage: tools/run-validation-vectors.sh [id-prefix]
set -euo pipefail
cd "$(dirname "$0")/.."
V=${ONECRYPTO_VECTORS:-$HOME/onecrypto/vectors}
export ONECRYPTO_LIMBO=$V/x509-limbo/limbo.json
export ONECRYPTO_LIMBO_RESULTS=${OUT:-$PWD/limbo.tsv}
[ $# -gt 0 ] && export ONECRYPTO_LIMBO_FILTER=$1
dotnet test --project tests/OneCrypto.Tests -c Release --filter-class '*LimboTests' 2>&1 | grep -v '^ *at ' | tail -20

# Summary: our verdict against the expected result, and the testcases where they differ (one line each in $OUT.mismatch).
cut -f2,3 "$ONECRYPTO_LIMBO_RESULTS" | sort | uniq -c
awk -F'\t' '{ok=($2=="SUCCESS"&&$3=="Valid")||($2=="FAILURE"&&$3!="Valid"); if(!ok) print}' "$ONECRYPTO_LIMBO_RESULTS" | cut -c1-240 | sort > "$ONECRYPTO_LIMBO_RESULTS.mismatch"
wc -l < "$ONECRYPTO_LIMBO_RESULTS.mismatch"
awk -F'\t' '{split($1,a,"::"); print a[1]}' "$ONECRYPTO_LIMBO_RESULTS.mismatch" | sort | uniq -c
