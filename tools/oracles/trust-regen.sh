#!/usr/bin/env bash
# Regenerates testdata/openpgp/trust: the scenarios (throwaway keys), what Sequoia's `sq pki authenticate` says about the flow ones, and what
# GnuPG's colon listing says about the classic ones. Run from the repository root. The oracles are only run, never read.
#
#   tools/oracles/trust-regen.sh [oracles-dir]        (default ~/onecrypto/oracles; needs python3, sq 1.5.0, GnuPG 2.5.24 and a system gpg)
#
# GnuPG 2.4.8 expectations are added separately where that version is installed:
#   python3 tools/oracles/trust-scenarios.py expect-gpg testdata/openpgp/trust --gpg /usr/bin/gpg
set -euo pipefail
ORACLES=${1:-$HOME/onecrypto/oracles}
OUT=testdata/openpgp/trust
SQ=$ORACLES/sequoia-sq-1.5.0/bin/sq
G25=$ORACLES/gnupg-2.5.24
export TMPDIR=${TMPDIR:-$HOME/onecrypto/u38/tmp}
mkdir -p "$TMPDIR"
rm -rf "$OUT"; mkdir -p "$OUT"
python3 tools/oracles/trust-scenarios.py generate "$OUT" --sq "$SQ" --gpg "$(command -v gpg)" 2> >(grep -v '^generated' >&2)
python3 tools/oracles/trust-scenarios.py expect-sq "$OUT" --sq "$SQ"
LD_LIBRARY_PATH=$G25/lib python3 tools/oracles/trust-scenarios.py expect-gpg "$OUT" --gpg "$G25/bin/gpg"
ls "$OUT" | wc -l
