#!/usr/bin/env bash
# The key-secret timing targets and the OpenPGP/CMS glue targets, split into groups that each fit a 20-minute slot on both reference
# machines (measured durations: docs/timing.md). N defaults to 1,000,000 calls per target, with the exceptions explained at group_n.
#
#   tools/timing-groups.sh list                       every group with its members and default N
#   tools/timing-groups.sh all                        the group names, one per line
#   tools/timing-groups.sh run <group> <outdir> [N]   one group through the queue (an indicative heavy job by default;
#                                                     PERF_CLASS=bench for a publishable exclusive run; PERF_MAX overrides 20m)
#
# Needs the .NET 10 SDK on PATH. Members are primitives (all their operations) or exact Primitive/operation entries.
# macOS ships bash 3.2, so no associative arrays: one case branch per group.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."

members() {
  case "$1" in
    small-and-glue) echo "Camellia-128 Camellia-256 CAST5 IDEA Twofish-128 Twofish-256 AES-OCB AES-EAX AES-KW ChaCha20-Poly1305 OpenPgpSessionKey/checksum-unpadded-v6-key-bytes OpenPgpSessionKey/checksum-unpadded-v6-key-bytes-control OpenPgpSessionKey/checksum-padded-ecdh-key-bytes OpenPgpSessionKey/checksum-padded-ecdh-key-bytes-control OpenPgpSessionKey/checksum-padded-ecdh-bad-padding-vs-bad-checksum OpenPgpSecretKeyUnlock CmsCbc" ;;
    curves) echo "Ed25519 Ed448 X25519 X448" ;;
    glue-pkesk-rsa) echo "OpenPgpSessionKey/pkesk-rsa-bad-padding-vs-bad-checksum" ;;
    blowfish-dk-?) echo "Blowfish/decrypt-key" ;;
    blowfish-ck-?) echo "Blowfish/control-decrypt-key" ;;
    blowfish-ks-?) echo "Blowfish/key-setup" ;;
    blowfish-cks-?) echo "Blowfish/control-key-setup Blowfish/decrypt-data" ;;
    *) return 1 ;;
  esac
}

# Blowfish builds a key object in 1.2 to 2.4 ms, so 1,000,000 calls would overrun a 20-minute slot on the slower machine: each Blowfish
# target runs as two independent halves of 500,000 calls (suffix -1 and -2), and both halves must pass. The RSA PKESK target is a
# platform residual with no timing claim (about 2.7 ms a call on arm64) and runs at 300,000.
group_n() {
  case "$1" in
    blowfish-*) echo 500000 ;;
    glue-pkesk-rsa) echo 300000 ;;
    *) echo 1000000 ;;
  esac
}

ORDER=(small-and-glue curves glue-pkesk-rsa blowfish-dk-1 blowfish-dk-2 blowfish-ck-1 blowfish-ck-2 blowfish-ks-1 blowfish-ks-2 blowfish-cks-1 blowfish-cks-2)

case "${1:-}" in
  list) for g in "${ORDER[@]}"; do echo "$g (N=$(group_n "$g")): $(members "$g")"; done ;;
  all) printf '%s\n' "${ORDER[@]}" ;;
  run)
    g=${2:?group}; out=${3:?outdir}
    mem=$(members "$g") || { echo "unknown group '$g'; try 'list'" >&2; exit 2; }
    n=${4:-$(group_n "$g")}
    export DOTNET_TieredCompilation=0 DOTNET_TieredPGO=0 DOTNET_ReadyToRun=0
    dotnet build -c Release tests/Timing/OneCrypto.Timing.csproj -v quiet -clp:NoSummary
    mkdir -p "$out"
    PERF_CORES=${PERF_CORES:-2} tools/perf-run.sh "$out" "${PERF_MAX:-20m}" "onecrypto timing group $g" -- \
      env TIMING_PRIMITIVES="$mem" tools/timing-keys.sh "$out" "$n"
    ;;
  *) echo "usage: tools/timing-groups.sh list|all|run <group> <outdir> [N]" >&2; exit 2 ;;
esac
