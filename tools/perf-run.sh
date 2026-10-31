#!/usr/bin/env bash
# Runs a command as an exclusive benchmark job under the machine's work queue, and records the machine's CPU, core count and
# load before, during and after into <outdir>/machine.txt and <outdir>/load.log.
#
#   tools/perf-run.sh <outdir> <max-duration> <label> -- <command...>
#
# Example: tools/perf-run.sh out/timing 20m "onecrypto timing selfcheck" -- dotnet run -c Release --project tests/Timing -- selfcheck
#
# The queue is the `wq` command; set PERF_NO_WQ=1 to run the command directly (for a machine without a queue).
#
# PERF_CLASS chooses the queue class and defaults to `heavy`: a run in that class is indicative, its label ends in
# "indicative" and its verdict says so. `bench` (exclusive machine, publishable numbers) only on explicit request:
# PERF_CLASS=bench. PERF_CORES (default 2) is the core count a heavy job reserves; <max-duration> must be at most 30m for heavy.
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

  # A timing taken beside other work is not a measurement. The run is flagged when the 1-minute load average before or during
  # it exceeds a threshold (2.0 on Linux, 1.5 on macOS; PERF_MAX_LOAD overrides). Publish only runs marked "publishable: yes".
  if [[ -n "${PERF_MAX_LOAD:-}" ]]; then limit=$PERF_MAX_LOAD; elif [[ -r /proc/cpuinfo ]]; then limit=2.0; else limit=1.5; fi
  peak=$(grep -E '^(before|during):' "$outdir/load.log" | sed -E 's/^(before:|during: [0-9:]+) *//' | tr -d ',' | awk '{print $1}' | sort -g | tail -1)
  if [[ "${PERF_CLASS:-heavy}" != bench ]]; then verdict="NO (indicative: ran as class ${PERF_CLASS:-heavy}, beside other work)"
  elif awk -v p="$peak" -v l="$limit" 'BEGIN{exit !(p<=l)}'; then verdict=yes; else verdict=NO; fi
  echo "publishable: $verdict (highest 1-minute load before/during: $peak, limit $limit)" | tee "$outdir/publishable.txt"
  exit "$rc"
fi

outdir=$1; max=$2; label=$3; shift 3
[[ "${1:-}" == "--" ]] && shift
self="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/perf-run.sh"
if [[ -n "${PERF_NO_WQ:-}" ]]; then
  exec "$self" --inner "$outdir" -- "$@"
fi
class=${PERF_CLASS:-heavy}
if [[ "$class" == bench ]]; then
  exec wq run --class bench --max "$max" --label "$label" -- "$self" --inner "$outdir" -- "$@"
fi
exec wq run --class "$class" --cores "${PERF_CORES:-2}" --max "$max" --label "$label indicative" -- "$self" --inner "$outdir" -- "$@"
