#!/usr/bin/env bash
# Benchmarks on a bench machine. Run from anywhere in the repository, with the .NET 10 SDK on PATH.
#
#   tools/bench.sh <outdir> [BenchmarkDotNet options...] [--quick]
#
#   tools/bench.sh results/bench-sha256 --filter '*Sha256Rows*'
#
# <outdir> is relative to the repository root so that `remote_run` can pull it back. It receives BenchmarkDotNet's reports
# (artifacts/), summary.json (per-area geomeans against the bar), machine.txt, load.log and publishable.txt.
# Runs as an indicative heavy job; PERF_CLASS=bench for a publishable exclusive run (see perf-run.sh).
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
out=$1; shift
dotnet build -c Release bench/OneCrypto.Benchmarks -v quiet -clp:NoSummary
mkdir -p "$out"
tools/perf-run.sh "$out" "${PERF_MAX:-30m}" "onecrypto bench $*" -- \
  dotnet run --no-build -c Release --project bench/OneCrypto.Benchmarks -- "$@" \
  --artifacts "$out/artifacts" --summary "$out/summary.json"
