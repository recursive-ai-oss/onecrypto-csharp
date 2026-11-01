#!/usr/bin/env bash
# Makes a certificate directory with Sequoia's sq (run as a black box) from a binary OpenPGP export, and records what sq itself reports about it,
# as a fixture for the cert-d reader. The extension file sq adds (names starting with an underscore) is removed.
#
#   tools/oracles/certd-sq.sh <sq-binary> <export.pgp> <output-dir>
set -euo pipefail
SQ=${1:?usage: certd-sq.sh <sq-binary> <export.pgp> <output-dir>}
IN=$(realpath "${2:?}")
OUT=$(realpath -m "${3:?}")   # sq wants an absolute store path
VER=${SQ_VERSION:-unknown}   # sq prints no plain version line; the caller names the release it installed
work=$(mktemp -d "${TMPDIR:-/tmp}/certd-sq.XXXXXX")
trap 'rm -rf "$work"' EXIT
rm -rf "$OUT"; mkdir -p "$OUT"
"$SQ" --home "$work/home" --cert-store "$OUT/cert-d" cert import "$IN" >"$OUT/sq-import.txt" 2>&1 || echo "sq cert import exited with $?" >> "$OUT/sq-import.txt"   # it reports unusable certificates through its exit status
"$SQ" --home "$work/home" --cert-store "$OUT/cert-d" cert list --gossip 2>&1 | sed 's/^/ /' > "$OUT/sq-cert-list.txt" || true
rm -f "$OUT"/cert-d/_*   # sq's own index and cache files (underscore names are extensions)
echo "$VER" > "$OUT/VERSION"
find "$OUT/cert-d" -type f | sed "s|$OUT/cert-d/||" | sort > "$OUT/files.txt"
