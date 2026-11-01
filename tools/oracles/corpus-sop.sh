#!/usr/bin/env bash
# Generates an OpenPGP corpus with a Stateless OpenPGP CLI driver (sqop, gosop, sop-openpgp-js, our own sop): secret keys,
# certificates, detached signatures, inline and cleartext signatures and encrypted messages, armored and binary, every profile the
# driver lists for generate-key. Throwaway keys only.
#
#   tools/oracles/corpus-sop.sh <output-dir> <label> <sop-command...>
# Layout as corpus-gnupg.sh: <output-dir>/<label>/{keys,certs,sigs,messages}/NAME.{pgp,asc}.
set -uo pipefail
OUT=${1:?usage: corpus-sop.sh <output-dir> <label> <sop-command...>}; LABEL=$2; shift 2
SOP=("$@")
dest=$OUT/$LABEL; rm -rf "$dest"; mkdir -p "$dest"/{keys,certs,sigs,messages}
w=$(mktemp -d "${TMPDIR:-/tmp}/corpus-sop.XXXXXX"); trap 'rm -rf "$w"' EXIT
log() { echo "[$LABEL] $*" >&2; }
profiles=$("${SOP[@]}" list-profiles generate-key 2>/dev/null | awk -F: 'NF{print $1}')
[ -n "$profiles" ] || profiles=default
printf 'throwaway message for the corpus\n' > "$w/msg"
printf 'throwaway-passphrase' > "$w/pw"
for prof in $profiles; do
  n=$(echo "$prof" | tr -c 'A-Za-z0-9\n' _)
  args=(); [ "$prof" != default ] && args=(--profile="$prof")
  for armor in armor no-armor; do
    ext=asc; flag=(); [ $armor = no-armor ] && { ext=pgp; flag=(--no-armor); }
    if ! "${SOP[@]}" generate-key "${args[@]}" "${flag[@]}" "Corpus $n <$n@corpus.invalid>" > "$dest/keys/$n.$ext" 2>"$w/err"; then
      log "generate-key $prof failed: $(head -c 200 "$w/err")"; rm -f "$dest/keys/$n.$ext"; continue
    fi
    "${SOP[@]}" extract-cert "${flag[@]}" < "$dest/keys/$n.$ext" > "$dest/certs/$n.$ext" 2>/dev/null || log "extract-cert $n failed"
  done
  k=$dest/keys/$n.pgp; c=$dest/certs/$n.pgp
  [ -s "$k" ] || continue
  "${SOP[@]}" sign --no-armor "$k" < "$w/msg" > "$dest/sigs/$n-detached.pgp" 2>/dev/null || log "sign $n failed"
  "${SOP[@]}" sign "$k" < "$w/msg" > "$dest/sigs/$n-detached.asc" 2>/dev/null
  "${SOP[@]}" inline-sign --no-armor "$k" < "$w/msg" > "$dest/messages/$n-inline.pgp" 2>/dev/null || log "inline-sign $n failed"
  "${SOP[@]}" inline-sign --as=clearsigned "$k" < "$w/msg" > "$dest/messages/$n-clear.asc" 2>/dev/null || log "clearsign $n failed"
  "${SOP[@]}" encrypt --no-armor "$c" < "$w/msg" > "$dest/messages/$n-enc.pgp" 2>/dev/null || log "encrypt $n failed"
  "${SOP[@]}" encrypt "$c" < "$w/msg" > "$dest/messages/$n-enc.asc" 2>/dev/null
  "${SOP[@]}" encrypt --no-armor --sign-with="$k" "$c" < "$w/msg" > "$dest/messages/$n-encsign.pgp" 2>/dev/null || log "encrypt+sign $n failed"
  "${SOP[@]}" encrypt --no-armor --with-password="$w/pw" < "$w/msg" > "$dest/messages/$n-pw.pgp" 2>/dev/null || log "password encrypt failed"
done
find "$dest" -type f -empty -delete
for d in keys certs sigs messages; do log "$d: $(ls "$dest/$d" | wc -l)"; done
