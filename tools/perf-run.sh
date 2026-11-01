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
  load1() { load | tr -d ',' | awk '{print $1}'; }
  mac_idle() { top -l 2 -n 0 -s 2 2>/dev/null | grep 'CPU usage' | tail -1 | sed -E 's/.* ([0-9.]+)% idle.*/\1/'; }
  # An exclusive slot opens the moment the queue drains, while the 1-minute load average still carries the jobs that just
  # finished. Wait (up to PERF_SETTLE seconds, default 180) for the machine to go quiet before measuring anything.
  if [[ "${PERF_CLASS:-heavy}" == bench ]]; then
    deadline=$(( $(date +%s) + ${PERF_SETTLE:-180} ))
    while (( $(date +%s) < deadline )); do
      if [[ -r /proc/cpuinfo ]]; then
        awk -v p="$(load1)" -v l="${PERF_MAX_LOAD:-2.0}" 'BEGIN{exit !(p<=l)}' && break
      else
        i=$(mac_idle); [[ -n "$i" ]] && awk -v i="$i" -v m="${PERF_MIN_IDLE:-90}" 'BEGIN{exit !(i>=m)}' && break
      fi
      sleep 10
    done
  fi
  echo "before: $(load)" > "$outdir/load.log"
  # macOS keeps a 1-minute load average near 2 with nothing running, so there the gate is the idle share of the CPU just
  # before the run (second sample of top, which measures over its interval).
  if [[ ! -r /proc/cpuinfo ]]; then
    idle=$(mac_idle)
    echo "idle-before: ${idle:-unknown}" >> "$outdir/load.log"
  fi
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

  # A timing taken beside other work is not a measurement. On Linux the run is flagged when the 1-minute load average before or
  # during it exceeds 2.0 (PERF_MAX_LOAD overrides); on macOS when the CPU is less than 90% idle just before it (PERF_MIN_IDLE).
  # Publish only runs marked "publishable: yes".
  peak=$(grep -E '^(before|during):' "$outdir/load.log" | sed -E 's/^(before:|during: [0-9:]+) *//' | tr -d ',' | awk '{print $1}' | sort -g | tail -1)
  if [[ "${PERF_CLASS:-heavy}" != bench ]]; then
    verdict="NO (indicative: ran as class ${PERF_CLASS:-heavy}, beside other work)"; basis="highest 1-minute load before/during: $peak"
  elif [[ -r /proc/cpuinfo ]]; then
    limit=${PERF_MAX_LOAD:-2.0}; basis="highest 1-minute load before/during: $peak, limit $limit"
    if awk -v p="$peak" -v l="$limit" 'BEGIN{exit !(p<=l)}'; then verdict=yes; else verdict=NO; fi
  else
    min=${PERF_MIN_IDLE:-90}; basis="CPU idle before start: ${idle:-unknown}%, minimum $min%"
    if [[ -n "${idle:-}" ]] && awk -v i="$idle" -v m="$min" 'BEGIN{exit !(i>=m)}'; then verdict=yes; else verdict=NO; fi
  fi
  echo "publishable: $verdict ($basis)" | tee "$outdir/publishable.txt"
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
