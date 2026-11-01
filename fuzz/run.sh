#!/usr/bin/env bash
# Build, instrument and run one fuzz target under libFuzzer.
#
#   fuzz/run.sh <target> <seconds> [corpus dir] [extra libFuzzer flags...]
#   fuzz/run.sh replay <target> <file>...      # run saved inputs once, without libFuzzer (reproduce a finding)
#
# Targets: cms, cmsenv, asn1, pem, x509, ocsp, verify, keys, pkcs8, pkcs12, ssh, validate, load, tsa, ocspresp, online, pades, placeholder, phc, pgppacket, gnupghome (see fuzz/README.md)
#
# Environment (nothing is baked into the script):
#   ONECRYPTO_FUZZ_WORK    required: where builds, corpora and findings go. Keep it outside the checkout.
#   ONECRYPTO_FUZZ_TOOLS   directory holding `fuzz/libfuzzer-dotnet` (the libFuzzer host) and `sharpfuzz/sharpfuzz` (the instrumenter).
#                          LIBFUZZER_DOTNET and SHARPFUZZ override the two paths individually.
#   ONECRYPTO_ARTIFACTS    build output root, as for every other project in the repo
#   DOTNET                 the dotnet executable (default: dotnet from PATH)
#   FUZZ_TIMEOUT           per-input timeout in seconds (default 10)
#   FUZZ_RSS_MB            memory limit in MB (default 1024)
set -euo pipefail

root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
dotnet_bin="${DOTNET:-dotnet}"
work="${ONECRYPTO_FUZZ_WORK:?set ONECRYPTO_FUZZ_WORK to a scratch directory outside the checkout}"
case "$(readlink -f "$work")/" in
  "$root"/*) echo "ONECRYPTO_FUZZ_WORK must be outside the checkout" >&2; exit 2 ;;
esac
tools="${ONECRYPTO_FUZZ_TOOLS:-}"
host="${LIBFUZZER_DOTNET:-$tools/fuzz/libfuzzer-dotnet}"
instrument="${SHARPFUZZ:-$tools/sharpfuzz/sharpfuzz}"

mode=fuzz
if [[ "${1:-}" == replay ]]; then
  mode=replay
  shift
fi
target="${1:?usage: run.sh <target> <seconds> [corpus dir] | run.sh replay <target> <file>...}"
shift

# Maximum input length per target.
case "$target" in
  cms|cmsenv) maxlen=131072 ;;
  asn1) maxlen=16384 ;;
  pem) maxlen=16384 ;;
  x509) maxlen=16384 ;;
  ocsp) maxlen=16384 ;;
  pkcs8) maxlen=16384 ;;
  pkcs12) maxlen=65536 ;;
  ssh) maxlen=16384 ;;
  validate) maxlen=16384 ;;
  verify) maxlen=1024 ;;
  keys) maxlen=16384 ;;
  load) maxlen=65536 ;;
  phc) maxlen=512 ;;
  pades) maxlen=131072 ;;
  placeholder) maxlen=65536 ;;
  tsa|ocspresp) maxlen=4096 ;;
  online) maxlen=16384 ;;
  pgppacket) maxlen=65536 ;;
  gnupghome) maxlen=65536 ;;
  *) echo "unknown target '$target'" >&2; exit 2 ;;
esac

proj=OneCrypto.Fuzz
# Only the library assembly is instrumented; the harness itself needs no coverage.
libs=(RecursiveAI.OneCrypto.dll OnePdf.dll RecursiveAI.OneCrypto.Pdf.dll RecursiveAI.OneCrypto.Online.dll RecursiveAI.OneCrypto.OpenPgp.dll)

bin="$work/bin"
rm -rf "$bin"
mkdir -p "$bin"
"$dotnet_bin" build "$root/fuzz/$proj/$proj.csproj" -c Release -v quiet -clp:NoSummary -o "$bin"

if [[ "$mode" == replay ]]; then
  ONECRYPTO_FUZZ_WORK="$work" "$dotnet_bin" "$bin/$proj.dll" replay "$target" "$@"
  exit $?
fi

seconds="${1:?usage: run.sh <target> <seconds> [corpus dir]}"
shift
extra=""
if [[ $# -gt 0 && "${1:0:1}" != "-" ]]; then
  extra="$1"
  shift
fi
[[ -x "$host" ]] || { echo "libFuzzer host not found at '$host' (set ONECRYPTO_FUZZ_TOOLS)" >&2; exit 2; }
[[ -x "$instrument" ]] || { echo "sharpfuzz not found at '$instrument' (set ONECRYPTO_FUZZ_TOOLS)" >&2; exit 2; }

export DOTNET_ROOT="${DOTNET_ROOT:-$(dirname "$(readlink -f "$(command -v "$dotnet_bin")")")}"
corpus="$work/corpus/$target"
findings="$work/findings/$target"
mkdir -p "$corpus" "$findings"

# Seeds come from the uninstrumented build (instrumented code needs libFuzzer's shared memory).
"$dotnet_bin" "$bin/$proj.dll" seeds "$target" "$corpus" >/dev/null
[[ -n "$(ls -A "$corpus")" ]] || printf '\x00' >"$corpus/seed-empty"

for lib in "${libs[@]}"; do
  "$instrument" "$bin/$lib" >/dev/null
done

# An extra seed directory is read-only for libFuzzer: new finds go to $corpus.
dirs=("$corpus")
[[ -z "$extra" ]] || dirs+=("$extra")

# -max_total_time bounds the run; crashes, hangs and out-of-memory inputs are written to the findings folder.
ONECRYPTO_FUZZ_TARGET="$target" ONECRYPTO_FUZZ_WORK="$work" "$host" \
  --target_path="$(command -v "$dotnet_bin")" --target_arg="$bin/$proj.dll" \
  -max_total_time="$seconds" -timeout="${FUZZ_TIMEOUT:-10}" -rss_limit_mb="${FUZZ_RSS_MB:-1024}" \
  -max_len="$maxlen" -artifact_prefix="$findings/" -print_final_stats=1 "$@" "${dirs[@]}"
