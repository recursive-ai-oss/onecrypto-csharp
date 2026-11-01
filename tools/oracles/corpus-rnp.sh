#!/usr/bin/env bash
# Generates an OpenPGP corpus with RNP (rnpkeys / rnp): keys of several algorithms, certificates, signatures and messages (SEIPD v1,
# AEAD where RNP offers it), armored and binary, with the fingerprints RNP lists. Throwaway keys and passphrases only.
#   tools/oracles/corpus-rnp.sh <rnp-install-dir> <output-dir> [label]
# <rnp-install-dir> is the extracted package root (contains usr/bin/rnp).
set -uo pipefail
R=${1:?usage: corpus-rnp.sh <rnp-install-dir> <output-dir> [label]}; OUT=${2:?}; LABEL=${3:-rnp}
export LD_LIBRARY_PATH=$R/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
RNP=$R/usr/bin/rnp RNPKEYS=$R/usr/bin/rnpkeys
dest=$OUT/$LABEL; rm -rf "$dest"; mkdir -p "$dest"/{keys,certs,sigs,messages}
w=$(mktemp -d "${TMPDIR:-/tmp}/corpus-rnp.XXXXXX"); trap 'rm -rf "$w"' EXIT
log() { echo "[$LABEL] $*" >&2; }
PW=throwaway-passphrase
printf 'throwaway message for the corpus\n' > "$w/msg"
# name | stdin for --expert (empty = default RSA 2048)
gen() { local name=$1 choices=$2 h=$w/home-$1; mkdir -p "$h"
  if [ -z "$choices" ]; then
    timeout 60 "$RNPKEYS" --homedir "$h" --numbits 2048 --userid "Corpus $name <$name@corpus.invalid>" --password "$PW" --generate-key --notty </dev/null >/dev/null 2>&1
  else
    printf "$choices" | timeout 60 "$RNPKEYS" --homedir "$h" --userid "Corpus $name <$name@corpus.invalid>" --password "$PW" --generate-key --expert --notty >/dev/null 2>&1
  fi || { log "generate $name failed"; return; }
  local uid="Corpus $name"
  for armor in armor binary; do
    local ext=pgp af=(); [ $armor = armor ] && { ext=asc; af=(--armor); }
    timeout 30 "$RNPKEYS" --homedir "$h" "${af[@]}" --export-key --secret --password "$PW" "$uid" --output "$dest/keys/$name.$ext" --overwrite --notty </dev/null >/dev/null 2>&1 || log "export secret $name $ext failed"
    timeout 30 "$RNPKEYS" --homedir "$h" "${af[@]}" --export-key "$uid" --output "$dest/certs/$name.$ext" --overwrite --notty </dev/null >/dev/null 2>&1 || log "export public $name $ext failed"
  done
  timeout 30 "$RNPKEYS" --homedir "$h" --list-keys 2>/dev/null | grep -E '^ +[0-9a-f]{40,64}$' | awk '{print "fpr:" toupper($1)}' > "$dest/certs/$name.fpr"
  cp "$dest/certs/$name.fpr" "$dest/keys/$name.fpr"
  local c
  for c in "-e" "-e --armor" "-e -s --password $PW" "-e --aead=OCB" "-e --aead=EAX --cipher AES256" "-e --cipher CAMELLIA128"; do
    local tag; tag=$(echo "$c" | tr -c 'A-Za-z0-9\n' _)
    timeout 30 "$RNP" --homedir "$h" $c -r "$uid" --password "$PW" --output "$dest/messages/$name-enc$tag.pgp" --overwrite --notty "$w/msg" </dev/null >/dev/null 2>&1 || { log "$name enc '$c' failed"; rm -f "$dest/messages/$name-enc$tag.pgp"; }
  done
  timeout 30 "$RNP" --homedir "$h" -c --password "$PW" --output "$dest/messages/$name-pw.pgp" --overwrite --notty "$w/msg" </dev/null >/dev/null 2>&1 || log "$name -c failed"
  timeout 30 "$RNP" --homedir "$h" -s --detach -u "$uid" --password "$PW" --output "$dest/sigs/$name-detached.pgp" --overwrite --notty "$w/msg" </dev/null >/dev/null 2>&1 || log "$name detach failed"
  timeout 30 "$RNP" --homedir "$h" -s --detach --armor -u "$uid" --password "$PW" --output "$dest/sigs/$name-detached.asc" --overwrite --notty "$w/msg" </dev/null >/dev/null 2>&1
  timeout 30 "$RNP" --homedir "$h" -s -u "$uid" --password "$PW" --output "$dest/messages/$name-inline.pgp" --overwrite --notty "$w/msg" </dev/null >/dev/null 2>&1 || log "$name sign failed"
  timeout 30 "$RNP" --homedir "$h" --clearsign -u "$uid" --password "$PW" --output "$dest/messages/$name-clear.asc" --overwrite --notty "$w/msg" </dev/null >/dev/null 2>&1 || log "$name clearsign failed"
}
gen rsa2048 ""
gen eddsa-x25519 "22\n"
gen ecdsa-p256 "19\n1\n"
gen ecdsa-p384 "19\n2\n"
gen ecdsa-p521 "19\n3\n"
gen dsa-elgamal "16\n"
find "$dest" -type f -empty -delete
for d in keys certs sigs messages; do log "$d: $(ls "$dest/$d" | wc -l)"; done
