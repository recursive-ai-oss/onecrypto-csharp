#!/usr/bin/env bash
# The key-secret timing targets and the OpenPGP/CMS glue targets, split into groups that each fit a 20-minute slot at N = 1,000,000
# on both reference machines (durations measured per group in docs/timing.md).
#
#   tools/timing-groups.sh list                    every group with its members
#   tools/timing-groups.sh run <group> <outdir> [N]   one group through the queue (indicative heavy job by default;
#                                                      PERF_CLASS=bench for a publishable exclusive run, PERF_MAX overrides 20m)
#   tools/timing-groups.sh all                     the group names, one per line
#
# Needs the .NET 10 SDK on PATH. Members are primitives (all their operations) or exact Primitive/operation entries.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

# macOS ships bash 3.2, so no associative arrays: one case branch per group.
members() {
  case "$1" in
    camellia) echo "Camellia-128 Camellia-256" ;;
    small-ciphers) echo "CAST5 IDEA" ;;
    blowfish-decrypt-key) echo "Blowfish/decrypt-key" ;;
    blowfish-control-key) echo "Blowfish/control-decrypt-key" ;;
    blowfish-setup) echo "Blowfish/key-setup Blowfish/control-key-setup Blowfish/decrypt-data" ;;
    twofish) echo "Twofish-128 Twofish-256" ;;
    aes-modes) echo "AES-OCB AES-EAX AES-KW" ;;
    curves) echo "Ed25519 Ed448 X25519 X448" ;;
    chacha) echo "ChaCha20-Poly1305" ;;
    glue-session-key) echo "OpenPgpSessionKey/checksum-unpadded-v6-key-bytes OpenPgpSessionKey/checksum-unpadded-v6-key-bytes-control OpenPgpSessionKey/checksum-padded-ecdh-key-bytes OpenPgpSessionKey/checksum-padded-ecdh-key-bytes-control OpenPgpSessionKey/checksum-padded-ecdh-bad-padding-vs-bad-checksum" ;;
    glue-pkesk-rsa) echo "OpenPgpSessionKey/pkesk-rsa-bad-padding-vs-bad-checksum" ;;
    glue-unlock-cms) echo "OpenPgpSecretKeyUnlock CmsCbc" ;;
    *) return 1 ;;
  esac
}
ORDER=(camellia small-ciphers blowfish-decrypt-key blowfish-control-key blowfish-setup twofish aes-modes curves chacha glue-session-key glue-pkesk-rsa glue-unlock-cms)

case "${1:-}" in
  list) for g in "${ORDER[@]}"; do echo "$g: $(members "$g")"; done ;;
  all) printf '%s\n' "${ORDER[@]}" ;;
  run)
    g=${2:?group}; out=${3:?outdir}; n=${4:-1000000}
    mem=$(members "$g") || { echo "unknown group '$g'; try 'list'" >&2; exit 2; }
    export DOTNET_TieredCompilation=0 DOTNET_TieredPGO=0 DOTNET_ReadyToRun=0
    dotnet build -c Release tests/Timing/OneCrypto.Timing.csproj -v quiet -clp:NoSummary
    mkdir -p "$out"
    PERF_CORES=${PERF_CORES:-2} tools/perf-run.sh "$out" "${PERF_MAX:-20m}" "onecrypto timing group $g" -- \
      env TIMING_PRIMITIVES="$mem" tools/timing-keys.sh "$out" "$n"
    ;;
  *) echo "usage: tools/timing-groups.sh list|all|run <group> <outdir> [N]" >&2; exit 2 ;;
esac
