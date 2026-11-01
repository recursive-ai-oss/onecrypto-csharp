#!/usr/bin/env bash
# Builds a GnuPG release (with the libraries it needs) from the published release tarballs with the standard configure/make
# toolchain, into $ONECRYPTO_ORACLES/gnupg-<version>. The result is run as a black box; the sources are never opened.
#   tools/oracles/gnupg.sh [2.5.24]
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
VER=${1:-2.5.24}
GPGERROR=1.61 GCRYPT=1.12.4 KSBA=1.8.1 ASSUAN=3.0.2 NPTH=1.8
base=https://gnupg.org/ftp/gcrypt
# Digests of the release tarballs as downloaded on 2026-11-01 (the upstream signatures are not checked here).
declare -A SHA=(
  [gnupg-2.5.24]="bf149d01a2b9fcc0e4589b8ae8697d3d5c557ea48ed95a3fa55dd3b1187e6039" [libgpg-error-$GPGERROR]="7a85413f2bc354f4f8aa832b718af122e48965e9e0eb9012ee659c13c6385c93" [libgcrypt-$GCRYPT]="d77f68f48879510e79a2f65977ccc68981781ea0923e5bdffac2a193ea3d660e" [libksba-$KSBA]="c2f84393011827219ae117131dba8e7684c2bed0961eed11b0642c2acba440b5" [libassuan-$ASSUAN]="d2931cdad266e633510f9970e1a2f346055e351bb19f9b78912475b8074c36f6" [npth-$NPTH]="8bd24b4f23a3065d6e5b26e98aba9ce783ea4fd781069c1b35d149694e90ca3e"
)
prefix=$ORACLES/gnupg-$VER
if [ -x "$prefix/bin/gpg" ]; then echo "gnupg $VER already installed"; exit 0; fi
work=$ORACLES/src/gnupg-build-$VER
mkdir -p "$work" && cd "$work"
build() { # name version dir url-dir extra-configure...
  local name=$1 ver=$2; shift 2
  fetch_pinned "$base/$name/$name-$ver.tar.bz2" "${SHA[$name-$ver]:-}" "$work/$name-$ver.tar.bz2"
  rm -rf "$name-$ver" && tar xjf "$name-$ver.tar.bz2" && (cd "$name-$ver" && ./configure --prefix="$prefix" "$@" >/dev/null && make -j4 >/dev/null && make install >/dev/null)
}
export PATH=$prefix/bin:$PATH LD_LIBRARY_PATH=$prefix/lib PKG_CONFIG_PATH=$prefix/lib/pkgconfig
build libgpg-error $GPGERROR --disable-doc --disable-tests
build libgcrypt $GCRYPT --disable-doc --with-libgpg-error-prefix="$prefix"
build libksba $KSBA --with-libgpg-error-prefix="$prefix"
build libassuan $ASSUAN --with-libgpg-error-prefix="$prefix"
build npth $NPTH
fetch_pinned "$base/gnupg/gnupg-$VER.tar.bz2" "${SHA[gnupg-$VER]:-}" "$work/gnupg-$VER.tar.bz2"
rm -rf "gnupg-$VER" && tar xjf "gnupg-$VER.tar.bz2"
(cd "gnupg-$VER" && ./configure --prefix="$prefix" --with-libgpg-error-prefix="$prefix" --with-libgcrypt-prefix="$prefix" \
  --with-libksba-prefix="$prefix" --with-libassuan-prefix="$prefix" --with-npth-prefix="$prefix" \
  --disable-doc --disable-tests --disable-ldap --disable-sqlite --disable-gnutls --disable-tpm2d --disable-ntbtls --disable-wks-tools \
  --disable-bzip2 --without-readline >/dev/null && make -j4 >/dev/null && make install >/dev/null)
"$prefix/bin/gpg" --version | head -3
