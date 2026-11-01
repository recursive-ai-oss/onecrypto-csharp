#!/usr/bin/env bash
# Runs a command at low priority and stops it if a benchmark takes the machine (the lock file appears). For downloads and the
# modest builds of oracles; anything heavier goes through the work queue instead.
#   tools/oracles/light.sh <command> [args...]
lock=$HOME/WORKER-BENCH.lock
while [ -e "$lock" ]; do sleep 30; done
setsid nice -n 19 "$@" &
pid=$!
( while kill -0 "$pid" 2>/dev/null; do
    if [ -e "$lock" ]; then kill -TERM -- "-$pid" 2>/dev/null || kill -TERM "$pid"; echo "stopped: a benchmark started" >&2; fi
    sleep 30
  done ) &
watch=$!
wait "$pid"
rc=$?
kill "$watch" 2>/dev/null
exit "$rc"
