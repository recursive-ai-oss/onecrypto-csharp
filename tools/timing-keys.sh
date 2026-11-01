#!/usr/bin/env bash
# Runs the key-secret timing targets (every key kind with its A/A control) and the curve targets, one log per primitive.
#
#   tools/timing-keys.sh <outdir> [N]
#
# TIMING_PRIMITIVES chooses what runs: primitives (all their operations) or exact Primitive/operation entries; TIMING_ONLY keeps the
# operations whose name contains the text. Each entry's wall time goes to <outdir>/durations.log. tools/timing-groups.sh splits the
# whole key-secret set into groups that each fit a 20-minute slot.
# Meant to run inside perf-run.sh or a queue job; needs the .NET 10 SDK on PATH.
set -uo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
out=$1; n=${2:-1000000}
export DOTNET_TieredCompilation=0 DOTNET_TieredPGO=0 DOTNET_ReadyToRun=0
dotnet build -c Release tests/Timing/OneCrypto.Timing.csproj -v quiet -clp:NoSummary || exit 1
mkdir -p "$out"
{ echo "cpu: $(grep -m1 'model name' /proc/cpuinfo 2>/dev/null || sysctl -n machdep.cpu.brand_string)"; echo "dotnet: $(dotnet --version)"; echo "n: $n"; } >> "$out/machine.txt"
for p in ${TIMING_PRIMITIVES:-Camellia-128 Camellia-256 CAST5 IDEA Blowfish Twofish-128 Twofish-256 AES-OCB AES-EAX AES-KW Ed25519 Ed448 X25519 X448 ChaCha20-Poly1305}; do
  echo "load before $p: $(uptime | sed 's/.*load average[s]*: //')" >> "$out/load.log"
  t0=$(date +%s)
  dotnet run --no-build -c Release --project tests/Timing/OneCrypto.Timing.csproj -- run "$p" --n "$n" ${TIMING_ONLY:+--only "$TIMING_ONLY"} >> "$out/${p////_}.log" 2>&1
  echo "load after $p: $(uptime | sed 's/.*load average[s]*: //')" >> "$out/load.log"
  echo "$p $(( $(date +%s) - t0 ))s" >> "$out/durations.log"
done
exit 0
