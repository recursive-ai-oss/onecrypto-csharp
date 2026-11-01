#!/usr/bin/env bash
# Generates an OpenPGP corpus with Sequoia's `sq`: v4 and v6 keys of every cipher suite it offers (post-quantum included),
# certificates, detached/inline/cleartext signatures and encrypted messages, armored and binary, with the fingerprints
# `sq inspect` prints. Throwaway keys and passphrases only.
#   tools/oracles/corpus-sq.sh <sq-binary> <output-dir> [label]
set -uo pipefail
SQ=${1:?usage: corpus-sq.sh <sq-binary> <output-dir> [label]}; OUT=${2:?}; LABEL=${3:-sq}
dest=$OUT/$LABEL; rm -rf "$dest"; mkdir -p "$dest"/{keys,certs,sigs,messages}
w=$(mktemp -d "${TMPDIR:-/tmp}/corpus-sq.XXXXXX"); trap 'rm -rf "$w"' EXIT
log() { echo "[$LABEL] $*" >&2; }
q() { "$SQ" --home "$w/home" --cert-store=none --key-store=none "$@"; }
mkdir -p "$w/home"
printf 'throwaway message for the corpus\n' > "$w/msg"
printf 'throwaway-passphrase' > "$w/pw"
for profile in rfc4880 rfc9580; do
  for suite in rsa2k rsa3k cv25519 cv448 mldsa65-ed25519 mldsa87-ed448; do
    n=$profile-$suite
    if ! q key generate --own-key --profile $profile --cipher-suite $suite --name "Corpus $n" --email "$n@corpus.invalid" --without-password \
         --output "$w/$n.key" --rev-cert "$w/$n.rev" >/dev/null 2>"$w/err"; then
      log "generate $n failed: $(tr '\n' ' ' < "$w/err" | head -c 160)"; continue
    fi
    cp "$w/$n.key" "$dest/keys/$n.pgp"
    q key generate --own-key --profile $profile --cipher-suite $suite --name "Corpus $n" --email "$n@corpus.invalid" --new-password-file "$w/pw" --output "$dest/keys/$n-locked.pgp" --rev-cert "$w/$n-l.rev" >/dev/null 2>&1
    q key delete --cert-file "$w/$n.key" --output "$dest/certs/$n.pgp" >/dev/null 2>&1 || log "key delete $n failed"
    cp "$w/$n.rev" "$dest/sigs/$n-revocation.pgp" 2>/dev/null
    q toolbox armor --help >/dev/null 2>&1
    q inspect "$dest/certs/$n.pgp" 2>/dev/null | grep -E 'Fingerprint:' | awk '{print "fpr:" toupper($NF)}' > "$dest/certs/$n.fpr"
    cp "$dest/certs/$n.fpr" "$dest/keys/$n.fpr"
    c="$dest/certs/$n.pgp"
    q sign --signer-file "$w/$n.key" --binary --signature-file "$dest/sigs/$n-detached.pgp" "$w/msg" >/dev/null 2>&1 || log "$n detached failed"
    q sign --signer-file "$w/$n.key" --message --binary --output "$dest/messages/$n-inline.pgp" "$w/msg" >/dev/null 2>&1 || log "$n inline failed"
    q sign --signer-file "$w/$n.key" --cleartext --output "$dest/messages/$n-clear.asc" "$w/msg" >/dev/null 2>&1 || log "$n clearsign failed"
    q encrypt --for-file "$c" --without-signature --binary --output "$dest/messages/$n-enc.pgp" "$w/msg" >/dev/null 2>&1 || log "$n encrypt failed"
    q encrypt --for-file "$c" --without-signature --output "$dest/messages/$n-enc.asc" "$w/msg" >/dev/null 2>&1
    q encrypt --for-file "$c" --signer-file "$w/$n.key" --binary --output "$dest/messages/$n-encsign.pgp" "$w/msg" >/dev/null 2>&1 || log "$n encrypt+sign failed"
    q encrypt --for-file "$c" --without-signature --binary --profile $profile --output "$dest/messages/$n-enc-$profile.pgp" "$w/msg" >/dev/null 2>&1
  done
done
q encrypt --with-password-file "$w/pw" --without-signature --binary --output "$dest/messages/pw.pgp" "$w/msg" >/dev/null 2>&1 || log "password encrypt failed"
find "$dest" -type f -empty -delete
for d in keys certs sigs messages; do log "$d: $(ls "$dest/$d" | wc -l)"; done
