#!/usr/bin/env bash
# Which key profiles can other OpenPGP implementations use? For each oracle and each profile we generate a key with our sop and check, one cell each:
#   import   the oracle reads our certificate
#   verify   the oracle verifies our detached signature
#   encrypt  the oracle encrypts to our certificate, and we decrypt it with the secret key
# Output is one markdown table row per oracle and profile. Every oracle is only executed.
# Usage: tools/oracles/profile-interop.sh "<our sop command>" <work dir> [oracle names...]
#   oracle names: sqop gosop pgpjs rnp gpg:<label>=<path to gpg> (default: sqop gosop pgpjs rnp, plus gpg from GPGS="label=path label=path")
set -u
OURS=${1:?our sop command}; W=${2:?work dir}; shift 2
ORACLES=${ONECRYPTO_ORACLES:-$HOME/onecrypto/oracles}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
mkdir -p "$W" && cd "$W" || exit 2
printf 'profile interop check\nsecond line\n' > msg.txt
profiles=${PROFILES:-"rfc9580 rfc9580-v4 draft-koch-eddsa-for-openpgp-00"}
UID1='Profile <profile@example.org>'

for p in $profiles; do
  $OURS generate-key --profile=$p "$UID1" > $p.key 2>/dev/null || { echo "our generate-key --profile=$p failed" >&2; continue; }
  $OURS extract-cert < $p.key > $p.cert
  $OURS sign $p.key < msg.txt > $p.sig
  $OURS dearmor < $p.cert > $p.cert.bin
  $OURS dearmor < $p.sig > $p.sig.bin
done

cell() { # name, command...
  local name=$1; shift
  if "$@" > cell.out 2> cell.err; then echo "ok"; else echo "FAIL($(grep -v 'created$' cell.err | grep -v '^$' | tail -n 2 | tr '\n|' '; ' | cut -c1-110))"; fi
}

row() { echo "| $1 | $2 | $3 | $4 | $5 | $6 |"; }

sop_oracle() { # label, command
  local label=$1 X=$2
  for p in $profiles; do
    [ -s $p.key ] || continue
    local i v e
    i="n/a"  # sop has no import: verify and encrypt read the certificate
    v=$(cell verify bash -c "$X verify $p.sig $p.cert < msg.txt")
    e=$(cell encrypt bash -c "$X encrypt $p.cert < msg.txt > $p.enc && $OURS decrypt $p.key < $p.enc | cmp - msg.txt")
    row "$label" "$p" "v$(ver_of $p)" "$i" "$v" "$e"
  done
}
ver_of() { python3 -c "
import sys
b=open('$1.cert.bin','rb').read(); t=b[0]
if t&0x40:
    l=b[1]; i=2 if l<192 else 3 if l<224 else 6
else:
    i=1+{0:1,1:2,2:4}[t&3]
print(b[i])"; }

gpg_oracle() { # label, gpg path
  local label=$1 G=$2
  local libdir; libdir=$(cd "$(dirname "$G")/../lib" 2>/dev/null && pwd); [ -n "$libdir" ] && export LD_LIBRARY_PATH=$libdir${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
  for p in $profiles; do
    [ -s $p.key ] || continue
    local h="$W/gpg-${label// /_}-$p" i v e fpr
    rm -rf "$h"; mkdir -m 700 "$h"
    i=$(cell import $G --homedir "$h" --batch --import $p.cert.bin)
    v=$(cell verify $G --homedir "$h" --batch --verify $p.sig.bin msg.txt)
    fpr=$($G --homedir "$h" --batch --with-colons --list-keys 2>/dev/null | awk -F: '/^fpr/{print $10; exit}')
    e=FAIL
    if [ -n "$fpr" ]; then
      e=$(cell encrypt bash -c "$G --homedir '$h' --batch --yes --trust-model always -r $fpr -o $p.gpg.enc -e msg.txt && $OURS decrypt $p.key < $p.gpg.enc | cmp - msg.txt")
    else
      e="FAIL(no key imported)"
    fi
    row "$label" "$p" "v$(ver_of $p)" "$i" "$v" "$e"
    $G --homedir "$h" --batch --list-keys >/dev/null 2>&1; gpgconf --homedir "$h" --kill all 2>/dev/null
  done
}

rnp_oracle() {
  local D=$ORACLES/rnp-distro
  export LD_LIBRARY_PATH=$D/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
  local RNP="$D/usr/bin/rnp --notty" RNPK="$D/usr/bin/rnpkeys --notty"
  local label="RNP $($D/usr/bin/rnp --version 2>/dev/null | head -1 | sed 's/^RNP version //; s/\+.*//')"
  for p in $profiles; do
    [ -s $p.key ] || continue
    local h="$W/rnp-$p" i v e
    rm -rf "$h"; mkdir -m 700 "$h"
    i=$(cell import $RNPK --homedir "$h" --import $p.cert.bin)
    cp $p.sig.bin msg.txt.sig
    v=$(cell verify $RNP --homedir "$h" --verify msg.txt.sig)
    e=$(cell encrypt bash -c "$RNP --homedir '$h' --recipient profile@example.org --encrypt --output $p.rnp.enc msg.txt --overwrite && $OURS decrypt $p.key < $p.rnp.enc | cmp - msg.txt")
    row "$label" "$p" "v$(ver_of $p)" "$i" "$v" "$e"
  done
}

echo "| oracle | profile | key | import | verify | encrypt, then ours decrypts |"
echo "|---|---|---|---|---|---|"
names=${*:-sqop gosop pgpjs rnp}
for n in $names; do
  case $n in
    sqop) sop_oracle "sqop $($ORACLES/sequoia-sop-nettle/bin/sqop version 2>&1 | head -1)" "$ORACLES/sequoia-sop-nettle/bin/sqop" ;;
    gosop) sop_oracle "gosop $($ORACLES/gosop-v1.1.0/gosop version 2>&1 | head -1 | awk '{print $2}')" "$ORACLES/gosop-v1.1.0/gosop" ;;
    pgpjs) OPENPGP_JS_DIR=${OPENPGP_JS_DIR:-$ORACLES/openpgpjs-6.3.2} sop_oracle "OpenPGP.js 6.3.2" "node $root/tools/oracles/pgpjs6/sop.mjs" ;;
    rnp) rnp_oracle ;;
    gpg:*) spec=${n#gpg:}; path=${spec#*=}; gpg_oracle "GnuPG $(LD_LIBRARY_PATH=$(dirname $path)/../lib:${LD_LIBRARY_PATH:-} $path --version | head -1 | awk '{print $3}')" "$path" ;;
  esac
done
