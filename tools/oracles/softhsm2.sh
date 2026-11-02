#!/usr/bin/env bash
# Installs SoftHSM2 user-locally (a software PKCS #11 token, run black-box only) and prints the module path:
#   tools/oracles/softhsm2.sh            -> prints the module path on the last line
#   eval "$(tools/oracles/softhsm2.sh --env)"   -> exports ONECRYPTO_SOFTHSM2_MODULE, _UTIL and a fresh SOFTHSM2_CONF (and the library path the Linux build needs)
# Linux: the distribution's `softhsm2` and `libsofthsm2` packages, downloaded with apt-get and extracted with dpkg -x, checked against the
# pinned SHA-256 below (a version without a pin is refused). macOS: the Homebrew bottle, extracted and re-pointed at the Homebrew OpenSSL 4
# (`brew install openssl@4` must exist; SoftHSM2 2.7.0, bottle sha256 b9879d4e…e326), then ad-hoc signed.
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
dir=$ORACLES/softhsm2
case "$(uname -s)" in
Linux)
  mod=$dir/usr/lib/softhsm/libsofthsm2.so
  if [ ! -f "$mod" ]; then
    mkdir -p "$dir/dl"
    (cd "$dir/dl" && apt-get download softhsm2 libsofthsm2 >/dev/null 2>&1)
    for d in "$dir"/dl/*.deb; do
      sum=$(sha256sum "$d" | cut -d' ' -f1)
      case "$sum" in
        # Ubuntu 26.04 (2.6.1-3) and Linux Mint 22 / Ubuntu 24.04 (2.6.1-2.2ubuntu3)
        6117da60dfc0ca0f28928af10a52ffa338bf9c99fa06669374d1aad53ad6a783|c9b76ced40eab91f7f6c106af45ebddc7f50c734d31639c57ceca26050d3665b) ;;
        438467b5602f4b936b7009eaf3a934eedbef6e9565a494a276e87739d89f0650|a15bf02be5d087c576d59ec16ea25b4a6302ed757d1c44d4295c79845be2d959) ;;
        *) echo "unpinned package $(basename "$d") sha256 $sum" >&2; exit 3 ;;
      esac
      dpkg -x "$d" "$dir"
    done
  fi
  [ -f "$mod" ] || mod=$(ls "$dir"/usr/lib/*/softhsm/libsofthsm2.so | head -1)
  export LD_LIBRARY_PATH=$dir/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
  ;;
Darwin)
  mod=$dir/lib/softhsm/libsofthsm2.so
  if [ ! -f "$mod" ]; then
    mkdir -p "$dir/dl"
    brew fetch --bottle-tag="${SOFTHSM_BOTTLE_TAG:-arm64_golden_gate}" softhsm >/dev/null
    tgz=$(brew --cache --bottle-tag="${SOFTHSM_BOTTLE_TAG:-arm64_golden_gate}" softhsm)
    [ "$(shasum -a 256 "$tgz" | cut -d' ' -f1)" = b9879d4e2e1afab76e20aad0009042903d3064ca7883ec16fd0d420c2176e326 ] || { echo "bottle checksum mismatch" >&2; exit 3; }
    tar -xzf "$tgz" -C "$dir/dl"
    cp -R "$dir"/dl/softhsm/*/* "$dir"/
    ssl=$(brew --prefix openssl@4)
    for f in "$mod" "$dir/bin/softhsm2-util"; do
      for dep in $(otool -L "$f" | awk '/@@HOMEBREW_PREFIX@@/{print $1}'); do
        install_name_tool -change "$dep" "$ssl/lib/$(basename "$dep")" "$f"
      done
      codesign -f -s - "$f"
    done
  fi
  ;;
esac
echo "$mod" > "$dir/MODULE"
if [ "${1:-}" = --env ]; then
  util=$(ls "$dir"/usr/bin/softhsm2-util "$dir"/bin/softhsm2-util 2>/dev/null | head -1 || true)
  # A fresh, empty token store for every run (the module reads SOFTHSM2_CONF when it starts, so it must be in the environment before the tests do).
  home=$(mktemp -d "${TMPDIR:-/tmp}/softhsm2-XXXXXX"); mkdir "$home/tokens"
  printf 'directories.tokendir = %s/tokens\nobjectstore.backend = file\nlog.level = ERROR\nslots.removable = false\n' "$home" > "$home/softhsm2.conf"
  echo "export ONECRYPTO_SOFTHSM2_MODULE='$mod' ONECRYPTO_SOFTHSM2_UTIL='$util' SOFTHSM2_CONF='$home/softhsm2.conf'"
  [ "$(uname -s)" = Linux ] && echo "export LD_LIBRARY_PATH='$dir/usr/lib/x86_64-linux-gnu':\${LD_LIBRARY_PATH:-}"
  "$util" --version | sed 's/^/# softhsm2-util /'
else
  echo "$mod"
fi
