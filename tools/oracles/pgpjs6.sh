#!/usr/bin/env bash
# Installs OpenPGP.js 6 (npm `openpgp`, pinned) into the oracle directory. It is only imported by our own corpus driver
# (pgpjs6/corpus.mjs, written against the documented public API); its files are never read.
#   tools/oracles/pgpjs6.sh [version]
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
export PATH=$HOME/onecrypto/tools/node/bin:$PATH
VER=${1:-6.3.2}
dir=$ORACLES/openpgpjs-$VER
if [ ! -d "$dir/node_modules/eckey-utils" ]; then
  mkdir -p "$dir"; (cd "$dir" && npm init -y >/dev/null && npm install --ignore-scripts --no-audit --no-fund "openpgp@$VER" eckey-utils 2>&1 | tail -3)
fi
cp "$(dirname "${BASH_SOURCE[0]}")/pgpjs6/corpus.mjs" "$dir/corpus.mjs"
echo "openpgp $VER at $dir"
