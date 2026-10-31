#!/usr/bin/env bash
# Timing tests on a bench machine. Run from the repository root, with the .NET 10 SDK on PATH.
#
#   tools/timing.sh <outdir> selfcheck|run <target> [--preset short|full] [--n N]
#
# Full-opt JIT (no tiering) is required for meaningful numbers; the harness records the setting. Results land in
# <outdir>/timing.json beside machine.txt and load.log.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
out=$1; shift
export DOTNET_TieredCompilation=0 DOTNET_TieredPGO=0 DOTNET_ReadyToRun=0
dotnet build -c Release tests/Timing/OneCrypto.Timing.csproj -v quiet -clp:NoSummary
mkdir -p "$out"
tools/perf-run.sh "$out" 20m "onecrypto timing $*" -- \
  dotnet run --no-build -c Release --project tests/Timing/OneCrypto.Timing.csproj -- "$@" --out "$out/timing.json"
