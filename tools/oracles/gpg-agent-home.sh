#!/usr/bin/env bash
# Builds a throwaway GnuPG home for the gpg-agent key backend tests, with a GnuPG binary (only run, never read).
#
#   tools/oracles/gpg-agent-home.sh <bin-dir-of-gnupg> <home-dir>
#
# The home holds one unprotected key per algorithm (RSA 3072, NIST P-256, Ed25519 with a Cv25519 subkey) and one RSA key protected by
# the passphrase "onecrypto-test". gpg-agent.conf points the agent at a scripted pinentry (pinentry-fake.sh) that answers from the file
# pinentry-mode in the home: "cancel" refuses like a user pressing Cancel, "hang" never answers, anything else is given as the passphrase. The file
# keys.tsv lists "name<TAB>fingerprint<TAB>sign-keygrip<TAB>encrypt-keygrip" for the tests. Nothing outside <home-dir> is touched; the
# agent is stopped again before the script ends.
set -euo pipefail
BIN=${1:?usage: gpg-agent-home.sh <gnupg-bin-dir> <home-dir>}
H=${2:?usage: gpg-agent-home.sh <gnupg-bin-dir> <home-dir>}
export PATH="$BIN:$PATH"
[ -d "$BIN/../lib" ] && export LD_LIBRARY_PATH="$BIN/../lib:${LD_LIBRARY_PATH:-}"
rm -rf "$H"; mkdir -p "$H"; chmod 700 "$H"; H=$(cd "$H" && pwd)
export GNUPGHOME=$H
cat > "$H/pinentry-fake.sh" <<EOF
#!/bin/sh
# Minimal Assuan pinentry for tests: GETPIN answers from the mode file next to this script.
mode=\$(cat "$H/pinentry-mode" 2>/dev/null)
echo "OK Pleased to meet you"
while read -r cmd rest; do
  case "\$cmd" in
    GETPIN)
      if [ "\$mode" = hang ]; then sleep 60; fi
      if [ "\$mode" = cancel ]; then echo "ERR 83886179 Operation cancelled <Pinentry>"; else echo "D \$mode"; echo "OK"; fi ;;
    BYE) echo "OK closing connection"; exit 0 ;;
    *) echo "OK" ;;
  esac
done
EOF
chmod 700 "$H/pinentry-fake.sh"
echo -n onecrypto-test > "$H/pinentry-mode"
printf 'pinentry-program %s/pinentry-fake.sh\nallow-loopback-pinentry\nno-grab\n' "$H" > "$H/gpg-agent.conf"
g() { gpg --batch --yes --quiet --pinentry-mode loopback --no-tty "$@"; }
: > "$H/keys.tsv"
grips() { gpg --homedir "$H" --list-secret-keys --with-colons --with-keygrip "$1" | awk -F: '/^(sec|ssb)/{k=$12; getline; getline; if ($1=="grp") print $10}'; }
mk() { # name algo subalgo pass
  local name=$1 algo=$2 sub=$3 pass=$4 uid fpr
  uid="Agent $name <$name@onecrypto.invalid>"
  g --passphrase "$pass" --quick-generate-key "$uid" "$algo" sign,cert never
  fpr=$(g --list-keys --with-colons "$uid" | awk -F: '/^fpr/{print $10; exit}')
  [ -n "$sub" ] && g --passphrase "$pass" --quick-add-key "$fpr" "$sub" encr never
  local sg eg
  sg=$(gpg --list-secret-keys --with-colons --with-keygrip "$fpr" | awk -F: '/^sec/{s=1} s&&/^grp/{print $10; exit}')
  eg=$(gpg --list-secret-keys --with-colons --with-keygrip "$fpr" | awk -F: '/^ssb/{s=1} s&&/^grp/{print $10; exit}')
  printf '%s\t%s\t%s\t%s\n' "$name" "$fpr" "$sg" "$eg" >> "$H/keys.tsv"
}
mk rsa rsa3072 rsa3072 ""
mk p256 nistp256 nistp256 ""
mk ed25519 ed25519 cv25519 ""
mk locked rsa2048 rsa2048 onecrypto-test
# GnuPG 2.5 can generate Ed448/X448 keys; 2.4 cannot, so this one is optional.
mk ed448 ed448 cv448 "" >/dev/null 2>&1 || true
awk -F'\t' '!($1=="ed448" && ($3=="" || $4==""))' "$H/keys.tsv" > "$H/keys.tmp" && mv "$H/keys.tmp" "$H/keys.tsv"
gpg --version | head -1 > "$H/VERSION"
gpgconf --homedir "$H" --kill all 2>/dev/null || true
echo "home ready: $H ($(wc -l < "$H/keys.tsv") keys)"
