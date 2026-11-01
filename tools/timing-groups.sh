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

declare -A G=(
  [camellia]="Camellia-128 Camellia-256"
  [small-ciphers]="CAST5 IDEA"
  [blowfish-decrypt-key]="Blowfish/decrypt-key"
  [blowfish-control-key]="Blowfish/control-decrypt-key"
  [blowfish-setup]="Blowfish/key-setup Blowfish/control-key-setup Blowfish/decrypt-data"
  [twofish]="Twofish-128 Twofish-256"
  [aes-modes]="AES-OCB AES-EAX AES-KW"
  [curves]="Ed25519 Ed448 X25519 X448"
  [chacha]="ChaCha20-Poly1305"
  [glue-session-key]="OpenPgpSessionKey/checksum-unpadded-v6-key-bytes OpenPgpSessionKey/checksum-unpadded-v6-key-bytes-control OpenPgpSessionKey/checksum-padded-ecdh-key-bytes OpenPgpSessionKey/checksum-padded-ecdh-key-bytes-control OpenPgpSessionKey/checksum-padded-ecdh-bad-padding-vs-bad-checksum"
  [glue-pkesk-rsa]="OpenPgpSessionKey/pkesk-rsa-bad-padding-vs-bad-checksum"
  [glue-unlock-cms]="OpenPgpSecretKeyUnlock CmsCbc"
)
ORDER=(camellia small-ciphers blowfish-decrypt-key blowfish-control-key blowfish-setup twofish aes-modes curves chacha glue-session-key glue-pkesk-rsa glue-unlock-cms)

case "${1:-}" in
  list) for g in "${ORDER[@]}"; do echo "$g: ${G[$g]}"; done ;;
  all) printf '%s\n' "${ORDER[@]}" ;;
  run)
    g=${2:?group}; out=${3:?outdir}; n=${4:-1000000}
    [[ -n "${G[$g]:-}" ]] || { echo "unknown group '$g'; try 'list'" >&2; exit 2; }
    export DOTNET_TieredCompilation=0 DOTNET_TieredPGO=0 DOTNET_ReadyToRun=0
    dotnet build -c Release tests/Timing/OneCrypto.Timing.csproj -v quiet -clp:NoSummary
    mkdir -p "$out"
    PERF_CORES=${PERF_CORES:-2} tools/perf-run.sh "$out" "${PERF_MAX:-20m}" "onecrypto timing group $g" -- \
      env TIMING_PRIMITIVES="${G[$g]}" tools/timing-keys.sh "$out" "$n"
    ;;
  *) echo "usage: tools/timing-groups.sh list|all|run <group> <outdir> [N]" >&2; exit 2 ;;
esac
