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
# PERF_CLASS=bench. On Linux, publishability is judged on the share of all CPUs that are busy (sampled from /proc/stat every 5 s
# before and during the run; iowait counts as idle), not on the load average, which also counts processes waiting on disk and so
# misjudges a quiet 32-thread host. Limits: PERF_MAX_BUSY (mean, default 8) and PERF_MAX_BUSY_SAMPLE (any one sample, default 15), in
# percent. A sample over the sample limit also records the busiest processes that are not part of this run. PERF_CORES (default 2) is the core count a heavy job reserves; <max-duration> must be at most 30m for heavy.
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

  # Busy share of all CPUs over a 5 s window, from /proc/stat (user+nice+system+irq+softirq+steal over everything but iowait counted idle).
  cpu_busy() {
    local a b
    a=$(head -1 /proc/stat); sleep "${1:-5}"; b=$(head -1 /proc/stat)
    awk -v a="$a" -v b="$b" 'BEGIN{n=split(a,x," ");split(b,y," ");t0=t1=0;for(i=2;i<=9;i++){t0+=x[i];t1+=y[i]}
      i0=x[5]+x[6];i1=y[5]+y[6];d=t1-t0;printf "%.1f\n",(d>0)?100*((d-(i1-i0))/d):0}'
  }
  # The busiest processes over 1 s that are not in this run's process group, for explaining a busy sample.
  others() {
    local g; g=$(ps -o pgid= -p $$ | tr -d ' ')
    top -b -n 2 -d 1 -w 200 -o %CPU 2>/dev/null | awk '/^ *PID/{n++;next} n==2 && NF>=12 && $9+0>=3 {print $1, $9"%", $12}' | while read -r pid cpu cmd; do
      [[ "$(ps -o pgid= -p "$pid" 2>/dev/null | tr -d ' ')" == "$g" ]] || echo "$pid $cpu $cmd"
    done | head -6 | tr '\n' ';'
  }
  load() { uptime | sed 's/.*load average[s]*: //'; }
  load1() { load | tr -d ',' | awk '{print $1}'; }
  mac_idle() { top -l 2 -n 0 -s 2 2>/dev/null | grep 'CPU usage' | tail -1 | sed -E 's/.* ([0-9.]+)% idle.*/\1/'; }
  # An exclusive slot opens the moment the queue drains, while the 1-minute load average still carries the jobs that just
  # finished. Wait (up to PERF_SETTLE seconds, default 180) for the machine to go quiet before measuring anything.
  if [[ "${PERF_CLASS:-heavy}" == bench ]]; then
    deadline=$(( $(date +%s) + ${PERF_SETTLE:-180} ))
    while (( $(date +%s) < deadline )); do
      if [[ -r /proc/stat ]]; then
        awk -v p="$(cpu_busy 5)" -v l="${PERF_MAX_BUSY_SAMPLE:-15}" 'BEGIN{exit !(p<=l)}' && break
      else
        i=$(mac_idle); [[ -n "$i" ]] && awk -v i="$i" -v m="${PERF_MIN_IDLE:-90}" 'BEGIN{exit !(i>=m)}' && break
        sleep 10
      fi
    done
  fi
  echo "before: $(load)" > "$outdir/load.log"
  # macOS keeps a 1-minute load average near 2 with nothing running, so there the gate is the idle share of the CPU just
  # before the run (second sample of top, which measures over its interval).
  if [[ ! -r /proc/cpuinfo ]]; then
    idle=$(mac_idle)
    echo "idle-before: ${idle:-unknown}" >> "$outdir/load.log"
  fi
  if [[ -r /proc/stat ]]; then
    # Sample the CPU-busy share (the 5 s window is the sleep) with the load average beside it; explain any sample over the limit.
    ( while true; do
        b=$(cpu_busy 5)
        echo "during: $(date -u +%T) $(load) busy=$b" >> "$outdir/load.log"
        if awk -v p="$b" -v l="${PERF_MAX_BUSY_SAMPLE:-15}" 'BEGIN{exit !(p>l)}'; then echo "others: $(date -u +%T) $(others)" >> "$outdir/load.log"; fi
      done ) &
  else
    ( while true; do echo "during: $(date -u +%T) $(load)" >> "$outdir/load.log"; sleep 5; done ) &
  fi
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
  if [[ -r /proc/stat ]]; then
    read -r mean peak < <(grep -oE 'busy=[0-9.]+' "$outdir/load.log" | cut -d= -f2 | awk '{s+=$1;if($1>m)m=$1;n++}END{printf "%.1f %.1f\n",(n?s/n:0),m}')
    basis="CPU busy during the run: mean ${mean:-n/a}%, worst 5 s sample ${peak:-n/a}%; limits ${PERF_MAX_BUSY:-8}% / ${PERF_MAX_BUSY_SAMPLE:-15}%"
    if [[ "${PERF_CLASS:-heavy}" != bench ]]; then verdict="NO (indicative: ran as class ${PERF_CLASS:-heavy}, beside other work)"
    elif [[ -n "${mean:-}" ]] && awk -v m="$mean" -v p="$peak" -v lm="${PERF_MAX_BUSY:-8}" -v lp="${PERF_MAX_BUSY_SAMPLE:-15}" 'BEGIN{exit !(m<=lm && p<=lp)}'; then verdict=yes; else verdict=NO; fi
  elif [[ "${PERF_CLASS:-heavy}" != bench ]]; then
    verdict="NO (indicative: ran as class ${PERF_CLASS:-heavy}, beside other work)"; basis="CPU idle before start: ${idle:-unknown}%"
  else
    min=${PERF_MIN_IDLE:-90}; basis="CPU idle before start: ${idle:-unknown}%, minimum $min%"
    if [[ -n "${idle:-}" ]] && awk -v i="$idle" -v m="$min" 'BEGIN{exit !(i>=m)}' ; then verdict=yes; else verdict=NO; fi
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
