#!/usr/bin/env bash
# Installs the Sequoia command-line tools `sq` (crate sequoia-sq) and `sqop` (crate sequoia-sop) with cargo, at pinned versions,
# using the pure-Rust crypto backend so that no system library is needed. cargo verifies the crates against the registry
# checksums; --locked uses each crate's published lockfile. The binaries are only executed.
#   tools/oracles/sequoia.sh [sq-version] [sqop-version]
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
export PATH=$HOME/.cargo/bin:$PATH
SQ=${1:-1.5.0} SQOP=${2:-0.38.0}
# Some dependencies still link OpenSSL; point them at the pinned OpenSSL oracle build and bake its library path into the binaries.
ossl=$ORACLES/openssl-3.5.9
libdir=$ossl/lib; [ -d "$ossl/lib64" ] && libdir=$ossl/lib64
export OPENSSL_DIR=$ossl OPENSSL_LIB_DIR=$libdir OPENSSL_INCLUDE_DIR=$ossl/include
export RUSTFLAGS="-C link-arg=-Wl,-rpath,$libdir"
features=crypto-rust,allow-experimental-crypto,allow-variable-time-crypto
if [ ! -x "$ORACLES/sequoia-sq-$SQ/bin/sq" ]; then
  cargo install sequoia-sq --version "$SQ" --locked --no-default-features --features "$features" --root "$ORACLES/sequoia-sq-$SQ"
fi
if [ ! -x "$ORACLES/sequoia-sop-$SQOP/bin/sqop" ]; then
  cargo install sequoia-sop --version "$SQOP" --locked --no-default-features --features crypto-rust --root "$ORACLES/sequoia-sop-$SQOP"
fi
"$ORACLES/sequoia-sq-$SQ/bin/sq" version | head -2
"$ORACLES/sequoia-sop-$SQOP/bin/sqop" version
