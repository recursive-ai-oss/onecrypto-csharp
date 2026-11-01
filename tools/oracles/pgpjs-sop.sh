#!/usr/bin/env bash
# Installs OpenPGP.js's sop driver from npm at a pinned version into $ONECRYPTO_ORACLES/pgpjs-sop-<version> and writes a
# `sop` launcher beside it. npm checks the package integrity hashes; the package is only executed.
#   tools/oracles/pgpjs-sop.sh [version]
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
export PATH=$HOME/onecrypto/tools/node/bin:$PATH
VER=${1:-0.1.1}
dir=$ORACLES/pgpjs-sop-$VER
if [ ! -d "$dir/node_modules" ]; then
  mkdir -p "$dir" && (cd "$dir" && npm init -y >/dev/null && npm install --no-audit --no-fund "sop-openpgp-js@$VER")
fi
ls "$dir/node_modules/.bin"
