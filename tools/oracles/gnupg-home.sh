#!/usr/bin/env bash
# Builds GnuPG home directories with a GnuPG binary, as fixtures for the home-directory readers: pubring.kbx, private-keys-v1.d,
# trustdb.gpg, a legacy keyring and what GnuPG itself reports about them (--with-colons listing, --export-ownertrust, --export).
# Everything is made in throwaway directories with throwaway keys; the passphrase of every protected key is "onecrypto-test".
# Nothing touches an existing home. GnuPG is only run, never read.
#
#   tools/oracles/gnupg-home.sh <gpg-binary> <output-dir> [label]
#
# Output: <output-dir>/<label>/{main,many,legacy}/ ... and <label>/VERSION.
#   main/    one unprotected and one protected key per algorithm GnuPG can make, a revoked key, an expired key, a key with two
#            user IDs, owner trust on some of them
#   many/    forty small keys
#   legacy/  the same main keys imported into pubring.gpg (the pre-keybox format, with GnuPG's ring-trust packets)
set -uo pipefail
GPG=${1:?usage: gnupg-home.sh <gpg-binary> <output-dir> [label]}
OUT=${2:?usage: gnupg-home.sh <gpg-binary> <output-dir> [label]}
GPG_VER=$("$GPG" --version | head -1 | awk '{print $NF}')
LABEL=${3:-$GPG_VER}
GBIN=$(dirname "$GPG")
export PATH="$GBIN:$PATH"
[ -n "${GNUPG_LIB:-}" ] && export LD_LIBRARY_PATH="$GNUPG_LIB:${LD_LIBRARY_PATH:-}"
PW=onecrypto-test
dest=$OUT/$LABEL
rm -rf "$dest"; mkdir -p "$dest"
work=$(mktemp -d "${TMPDIR:-/tmp}/gnupg-home.XXXXXX"); chmod 700 "$work"
trap 'for h in "$work"/*/; do "$GBIN/gpgconf" --homedir "$h" --kill all 2>/dev/null; done; rm -rf "$work"' EXIT
log() { echo "[$LABEL] $*" >&2; }

newhome() { # name -> sets H
  H=$work/$1; mkdir -p "$H"; chmod 700 "$H"
  printf 'allow-loopback-pinentry\n' > "$H/gpg-agent.conf"
}
g() { "$GPG" --homedir "$H" --batch --yes --pinentry-mode loopback --no-tty "$@"; }

# key NAME ALGO [SUBALGO] [PASS] [EXPIRE] [FAKED-TIME]
key() {
  local name=$1 algo=$2 sub=${3:-} pass=${4:-} exp=${5:-never} faked=${6:-}
  local uid="Test $name <$name@onecrypto.invalid>"
  local ft=(); [ -n "$faked" ] && ft=(--faked-system-time "$faked")
  if ! g "${ft[@]}" --passphrase "$pass" --quick-generate-key "$uid" "$algo" sign,cert "$exp" >/dev/null 2>&1; then log "skip $name ($algo)"; return 1; fi
  local fpr; fpr=$(g --list-keys --with-colons "$uid" | awk -F: '/^fpr/{print $10; exit}')
  [ -n "$sub" ] && g "${ft[@]}" --passphrase "$pass" --quick-add-key "$fpr" "$sub" encr "$exp" >/dev/null 2>&1
  echo "$fpr"
}

snapshot() { # copies the home's files into $dest/$1 and records GnuPG's own view
  local out=$dest/$1; mkdir -p "$out"
  g --list-keys --with-colons --with-fingerprint --with-subkey-fingerprint --fixed-list-mode > "$out/list-keys.colons" 2>/dev/null
  g --export-ownertrust > "$out/ownertrust.txt" 2>/dev/null
  g --export > "$out/export.pgp" 2>/dev/null
  "$GBIN/gpgconf" --homedir "$H" --kill all 2>/dev/null
  for f in pubring.kbx pubring.gpg trustdb.gpg; do [ -f "$H/$f" ] && cp "$H/$f" "$out/"; done
  [ -d "$H/private-keys-v1.d" ] && cp -r "$H/private-keys-v1.d" "$out/"
  ( "$GBIN/kbxutil" "$out/pubring.kbx" > "$out/kbxutil.txt" 2>&1 ) || true
}

algos="rsa2048:rsa2048 nistp256:nistp256 nistp384:nistp384 brainpoolP256r1:brainpoolP256r1 ed25519:cv25519 ed448:cv448"

newhome main
fprs=()
for pair in $algos; do
  a=${pair%%:*}; s=${pair##*:}
  f=$(key "u-$a" "$a" "$s" "") && echo "u-$a $f" >> "$H.keys"
  f=$(key "p-$a" "$a" "$s" "$PW") && echo "p-$a $f" >> "$H.keys"
done
# revoked, expired, two user IDs
f=$(key revoked ed25519 cv25519 "") && { g --passphrase "" --quick-revoke-uid "$f" "Test revoked <revoked@onecrypto.invalid>" >/dev/null 2>&1; g --passphrase "" --gen-revoke "$f" --output "$H/rev.asc" <<< $'y\n0\n\ny\n' >/dev/null 2>&1; g --import "$H/rev.asc" >/dev/null 2>&1; echo "revoked $f" >> "$H.keys"; }
f=$(key expired ed25519 cv25519 "" 1d 20200101T000000) && echo "expired $f" >> "$H.keys"
f=$(key twouid rsa2048 "" "") && { g --passphrase "" --quick-add-uid "$f" "Second Name <second@onecrypto.invalid>" >/dev/null 2>&1; echo "twouid $f" >> "$H.keys"; }
# owner trust: marginal, full, ultimate, never, undefined
i=0
for lvl in 4 5 6 3; do
  i=$((i+1)); line=$(sed -n "${i}p" "$H.keys"); [ -z "$line" ] && break
  echo "$(echo "$line" | awk '{print $2}'):$lvl:" | g --import-ownertrust >/dev/null 2>&1
done
cp "$H.keys" "$dest/main.keys"
snapshot main

newhome many
for n in $(seq 1 40); do key "m$n" ed25519 "" "" >/dev/null; done
snapshot many

# one home with an X.509 certificate imported by gpgsm beside an OpenPGP key, and where supported a key with a Kyber subkey (version 5 packets)
newhome special
key sp-ed25519 ed25519 "" "" >/dev/null
if openssl req -x509 -newkey rsa:2048 -nodes -keyout "$H/x.key" -out "$H/x.crt" -days 3650 -subj '/CN=onecrypto x509 test/O=Test' >/dev/null 2>&1; then
  "$GBIN/gpgsm" --homedir "$H" --batch --import "$H/x.crt" >/dev/null 2>&1 || log "gpgsm import failed"
fi
f=$(g --list-keys --with-colons | awk -F: '/^fpr/{print $10; exit}')
g --passphrase "" --quick-add-key "$f" ky768_cv25519 encr never >/dev/null 2>&1 || log "no Kyber subkey"
snapshot special
rm -f "$dest/special/private-keys-v1.d"/*.key.tmp 2>/dev/null

# the legacy keyring: import the main certificates into a file whose name selects the pre-keybox format
newhome legacy
mkdir -p "$dest/legacy"
: > "$H/pubring.gpg"   # an existing empty file is kept in the pre-keybox format
g --no-default-keyring --keyring "$H/pubring.gpg" --import "$dest/main/export.pgp" >/dev/null 2>&1
g --no-default-keyring --keyring "$H/pubring.gpg" --export > "$dest/legacy/export.pgp" 2>/dev/null
g --no-default-keyring --keyring "$H/pubring.gpg" --list-keys --with-colons --with-fingerprint --with-subkey-fingerprint --fixed-list-mode > "$dest/legacy/list-keys.colons" 2>/dev/null
cp "$H/pubring.gpg" "$dest/legacy/pubring.gpg" 2>/dev/null || log "no legacy keyring produced"
echo "$GPG_VER" > "$dest/VERSION"
log "done"
