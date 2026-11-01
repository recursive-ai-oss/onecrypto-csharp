#!/usr/bin/env bash
# Builds GnuPG 2.2.x from its published release tarball, reusing the libraries that tools/oracles/gnupg.sh installed for 2.5.x, into
# $ORACLES/gnupg-<version>. 2.2 is the last series whose agent protects keys with openpgp-s2k3-sha1-aes-cbc, which the key-file reader has to
# open. The result is run as a black box; the sources are never opened.
#   tools/oracles/gnupg22.sh [2.2.45]
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
VER=${1:-2.2.45}
LIBS=${ONECRYPTO_GNUPG_LIBS:-$ORACLES/gnupg-2.5.24}
declare -A SHA=([gnupg-2.2.45]="")
prefix=$ORACLES/gnupg-$VER
if [ -x "$prefix/bin/gpg" ]; then echo "gnupg $VER already installed"; exit 0; fi
[ -x "$LIBS/bin/gpg" ] || { echo "install tools/oracles/gnupg.sh first (its libraries are reused)" >&2; exit 1; }
work=$ORACLES/src/gnupg-build-$VER
mkdir -p "$work" && cd "$work"
fetch_pinned "https://gnupg.org/ftp/gcrypt/gnupg/gnupg-$VER.tar.bz2" "${SHA[gnupg-$VER]:-}" "$work/gnupg-$VER.tar.bz2"
rm -rf "gnupg-$VER" && tar xjf "gnupg-$VER.tar.bz2"
export PATH=$LIBS/bin:$PATH LD_LIBRARY_PATH=$LIBS/lib
(cd "gnupg-$VER" && ./configure --prefix="$prefix" --with-libgpg-error-prefix="$LIBS" --with-libgcrypt-prefix="$LIBS" \
  --with-libksba-prefix="$LIBS" --with-libassuan-prefix="$LIBS" --with-npth-prefix="$LIBS" \
  --disable-doc --disable-ldap --disable-sqlite --disable-gnutls --disable-bzip2 --disable-nls --without-readline --disable-tests >/dev/null && make -j4 >/dev/null && make install >/dev/null)
"$prefix/bin/gpg" --version | head -3
