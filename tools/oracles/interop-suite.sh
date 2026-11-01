#!/usr/bin/env bash
# Fetches the OpenPGP interoperability test suite at a pinned commit and builds it with cargo. It is run as a black box
# against sop drivers; its sources are never read. GPLv3: fetch-only, nothing from it is committed.
#   tools/oracles/interop-suite.sh
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
export PATH=$HOME/.cargo/bin:$PATH
COMMIT=601692566e9d5ac5ac904cfe6d1fd4ea3361c88a
dir=$ORACLES/interop-suite-${COMMIT:0:8}
# The suite links nettle through bindgen. Take the distro's nettle/gmp development files (extracted user-locally) and the
# libclang wheel from PyPI; nothing is installed system-wide.
dev=$ORACLES/nettle-distro
if [ ! -f "$dev/usr/include/nettle/nettle-meta.h" ]; then
  mkdir -p "$dev/dl"
  (cd "$dev/dl" && apt-get download nettle-dev libnettle8t64 libhogweed6t64 libgmp-dev libgmp10 libgmpxx4ldbl 2>&1 | tail -2)
  for d in "$dev"/dl/*.deb; do dpkg -x "$d" "$dev"; done
fi
if [ ! -d "$ORACLES/libclang-venv" ]; then
  "$HOME/.local/bin/uv" venv --python 3.13 "$ORACLES/libclang-venv" >/dev/null && "$HOME/.local/bin/uv" pip install --python "$ORACLES/libclang-venv/bin/python" libclang >/dev/null
fi
clangdir=$(dirname "$(find "$ORACLES/libclang-venv" -name 'libclang*.so*' | head -1)")
gccinc=$(dirname "$(gcc -print-file-name=include/stddef.h)")
mlib=$dev/usr/lib/x86_64-linux-gnu
export LIBCLANG_PATH=$clangdir
export BINDGEN_EXTRA_CLANG_ARGS="-I$gccinc -I$dev/usr/include -I$dev/usr/include/x86_64-linux-gnu"
export PKG_CONFIG_PATH=$mlib/pkgconfig PKG_CONFIG_SYSROOT_DIR=$dev PKG_CONFIG_ALLOW_SYSTEM_CFLAGS=1
export CPATH=$dev/usr/include:$dev/usr/include/x86_64-linux-gnu
export LIBRARY_PATH=$mlib LD_LIBRARY_PATH=$mlib${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
mkdir -p "$ORACLES/sqlite-link"
ln -sf "$(ls /usr/lib/x86_64-linux-gnu/libsqlite3.so.0 /lib/x86_64-linux-gnu/libsqlite3.so.0 2>/dev/null | head -1)" "$ORACLES/sqlite-link/libsqlite3.so"
export RUSTFLAGS="-C link-arg=-Wl,-rpath,$mlib -L $mlib -L $ORACLES/sqlite-link"
if [ ! -x "$dir/bin/openpgp-interoperability-test-suite" ] || [ ! -x "$ORACLES/sequoia-sop-nettle/bin/sqop" ]; then
  mkdir -p "$ORACLES/src"
  tarball=$ORACLES/src/interop-suite-$COMMIT.tar.gz
  [ -s "$tarball" ] || curl -fsSL -o "$tarball" "https://gitlab.com/sequoia-pgp/openpgp-interoperability-test-suite/-/archive/$COMMIT/openpgp-interoperability-test-suite-$COMMIT.tar.gz"
  sha256sum "$tarball"
  if [ ! -d "$dir.build/src" ]; then rm -rf "$dir.build"; mkdir -p "$dir.build"; tar -xzf "$tarball" -C "$dir.build" --strip-components=1; fi
  (cd "$dir.build" && cargo build --release 2>&1 | tail -15)
  mkdir -p "$dir/bin"; cp "$dir.build/target/release/openpgp-interoperability-test-suite" "$dir/bin/"
  # The suite builds Sequoia's sop driver (nettle backend) as part of itself; keep it as the sqop oracle.
  mkdir -p "$ORACLES/sequoia-sop-nettle/bin"; cp "$(find "$dir.build/target/release/build" -path "*artifact/bin/sqop" | head -1)" "$ORACLES/sequoia-sop-nettle/bin/"
fi
"$dir/bin/openpgp-interoperability-test-suite" --version
