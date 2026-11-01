# Shared helpers for the oracle fetch scripts. Sourced, not run.
# Oracles are installed user-locally under $ONECRYPTO_ORACLES (default ~/onecrypto/oracles), pinned by version and SHA-256,
# and are only ever executed: their sources are never opened.
set -euo pipefail
ORACLES=${ONECRYPTO_ORACLES:-$HOME/onecrypto/oracles}
mkdir -p "$ORACLES" "$ORACLES/src"

# fetch_pinned URL SHA256 FILE: downloads URL to FILE and checks the digest. An empty SHA256 prints the digest and fails unless
# ONECRYPTO_ALLOW_UNPINNED=1 (used once, to learn the digest of a new pin).
fetch_pinned() {
  local url=$1 sha=$2 file=$3
  if [ ! -s "$file" ]; then
    curl -fsSL --retry 3 -o "$file" "$url"
  fi
  local actual
  actual=$(sha256sum "$file" | cut -d' ' -f1)
  if [ -z "$sha" ]; then
    echo "sha256 $actual  $(basename "$file")  <- $url"
    [ "${ONECRYPTO_ALLOW_UNPINNED:-0}" = 1 ] || { echo "no pin for $url" >&2; return 3; }
  elif [ "$actual" != "$sha" ]; then
    echo "checksum mismatch for $url: expected $sha, got $actual" >&2
    rm -f "$file"
    return 1
  fi
}
