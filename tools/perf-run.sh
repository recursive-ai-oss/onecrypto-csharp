#!/usr/bin/env bash
# Runs a command as an exclusive benchmark job under the machine's work queue, and records the machine's CPU, core count and
# load before, during and after into <outdir>/machine.txt and <outdir>/load.log.
#
#   tools/perf-run.sh <outdir> <max-duration> <label> -- <command...>
#
# Example: tools/perf-run.sh out/timing 20m "onecrypto timing selfcheck" -- dotnet run -c Release --project tests/Timing -- selfcheck
#
# The queue is the `wq` command; set PERF_NO_WQ=1 to run the command directly (for a machine without a queue).
set -euo pipefail

if [[ "${1:-}" == "--inner" ]]; then
  outdir=$2; shift 3   # --inner <outdir> -- <command...>
  mkdir -p "$outdir"
  {
    echo "date: $(date -u +%FT%TZ)"
    echo "kernel: $(uname -srm)"
    if [[ -r /proc/cpuinfo ]]; then
      echo "cpu: $(grep -m1 'model name' /proc/cpuinfo | cut -d: -f2- | sed 's/^ //')"
      echo "cores: $(nproc)"
      echo "flags: $(grep -m1 '^flags' /proc/cpuinfo | cut -d: -f2- | tr ' ' '\n' | grep -E '^(avx|avx2|avx512f|sha_ni|aes|pclmulqdq|bmi2|adx)$' | tr '\n' ' ')"
    else
      echo "cpu: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m)"
      echo "cores: $(sysctl -n hw.ncpu)"
    fi
    echo "dotnet: $(dotnet --version)"
  } > "$outdir/machine.txt"

  load() { uptime | sed 's/.*load average[s]*: //'; }
  echo "before: $(load)" > "$outdir/load.log"
  ( while true; do echo "during: $(date -u +%T) $(load)" >> "$outdir/load.log"; sleep 5; done ) &
  sampler=$!
  disown "$sampler"
  trap 'kill $sampler 2>/dev/null || true' EXIT
  set +e
  "$@"
  rc=$?
  set -e
  kill "$sampler" 2>/dev/null || true
  echo "after: $(load)" >> "$outdir/load.log"
  exit "$rc"
fi

outdir=$1; max=$2; label=$3; shift 3
[[ "${1:-}" == "--" ]] && shift
self="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/perf-run.sh"
if [[ -n "${PERF_NO_WQ:-}" ]]; then
  exec "$self" --inner "$outdir" -- "$@"
fi
exec wq run --class bench --max "$max" --label "$label" -- "$self" --inner "$outdir" -- "$@"
