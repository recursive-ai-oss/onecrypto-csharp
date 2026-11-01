#!/usr/bin/env bash
# Generates an OpenPGP corpus with a GnuPG binary: keys, certificates, signatures and messages in many shapes, each as binary and armor,
# with the fingerprints GnuPG reports for every key (--with-colons) beside them. Everything is made in a throwaway home directory with
# throwaway keys and passphrases; nothing here touches an existing keyring.
#
#   tools/oracles/corpus-gnupg.sh <gpg-binary> <output-dir> [label]
#
# Output layout: <output-dir>/<label>/{keys,certs,sigs,messages}/NAME.{pgp,asc} and, for keys and certs, NAME.fpr (one line per key
# packet, primary first: "fpr:<hex>" as GnuPG prints it).
set -uo pipefail
GPG=${1:?usage: corpus-gnupg.sh <gpg-binary> <output-dir> [label]}
OUT=${2:?usage: corpus-gnupg.sh <gpg-binary> <output-dir> [label]}
LABEL=${3:-gnupg}
GPG_VER=$("$GPG" --version | head -1 | awk '{print $NF}')
dest=$OUT/$LABEL
rm -rf "$dest"
mkdir -p "$dest"/{keys,certs,sigs,messages}
home=$(mktemp -d "${TMPDIR:-/tmp}/corpus-gnupg.XXXXXX")
chmod 700 "$home"
trap 'gpgconf --homedir "$home" --kill all 2>/dev/null; rm -rf "$home"' EXIT
export GNUPGHOME=$home
printf 'allow-loopback-pinentry\n' > "$home/gpg-agent.conf"
g() { "$GPG" --homedir "$home" --batch --yes --pinentry-mode loopback --no-tty "$@"; }
PW=throwaway-passphrase
log() { echo "[$LABEL $GPG_VER] $*" >&2; }

# gen NAME ALGO [USAGE] [PASSPHRASE]: a primary key plus, when ALGO is an encryption-capable pair, a subkey
gen() {
  local name=$1 algo=$2 sub=${3:-} pass=${4:-}
  local uid="Corpus $name <$name@corpus.invalid>"
  local pf=(--passphrase "${pass}")
  [ -z "$pass" ] && pf=(--passphrase '')
  if ! g "${pf[@]}" --quick-generate-key "$uid" "$algo" sign never 2>/dev/null; then log "skip $name ($algo unsupported)"; return 1; fi
  local fpr
  fpr=$(g --list-keys --with-colons "$uid" | awk -F: '/^fpr/ {print $10; exit}')
  if [ -n "$sub" ]; then g "${pf[@]}" --quick-add-key "$fpr" "$sub" encr never 2>/dev/null || log "no subkey for $name ($sub)"; fi
  export_key "$name" "$fpr" "$pass"
  echo "$fpr"
}

# export_key NAME FPR [PASSPHRASE]: public, secret and fingerprints
export_key() {
  local name=$1 fpr=$2 pass=${3:-}
  g --export "$fpr" > "$dest/certs/$name.pgp"
  g --armor --export "$fpr" > "$dest/certs/$name.asc"
  g --list-keys --with-colons "$fpr" | awk -F: '/^fpr/ {print "fpr:" $10}' > "$dest/certs/$name.fpr"
  g --passphrase "$pass" --export-secret-keys "$fpr" > "$dest/keys/$name.pgp" 2>/dev/null
  g --passphrase "$pass" --armor --export-secret-keys "$fpr" > "$dest/keys/$name.asc" 2>/dev/null
  cp "$dest/certs/$name.fpr" "$dest/keys/$name.fpr"
}

declare -A FPR
for spec in \
  "rsa2048:rsa2048:rsa2048" "rsa3072:rsa3072:rsa3072" "rsa4096:rsa4096:rsa4096" \
  "dsa2048:dsa2048:elg2048" \
  "ed25519:ed25519:cv25519" \
  "p256:nistp256:nistp256" "p384:nistp384:nistp384" "p521:nistp521:nistp521" \
  "bp256:brainpoolP256r1:brainpoolP256r1" "bp384:brainpoolP384r1:brainpoolP384r1" "bp512:brainpoolP512r1:brainpoolP512r1" \
  "k256:secp256k1:secp256k1" \
  "ed448:ed448:cv448" "kyber768:ed25519:ky768_cv25519" "kyber1024:ed448:ky1024_cv448" ; do
  IFS=: read -r name algo sub <<< "$spec"
  FPR[$name]=$(gen "$name" "$algo" "$sub" "" | tail -1) && log "key $name ${FPR[$name]}" || unset 'FPR[$name]'
done

# Protected secret keys with different S2K settings.
for spec in "pw-iter-aes256:AES256:SHA256:3" "pw-iter-aes128:AES128:SHA1:3" "pw-salted-cast5:CAST5:SHA512:1" "pw-iter-3des:3DES:SHA256:3" "pw-iter-twofish:TWOFISH:SHA384:3" "pw-iter-camellia:CAMELLIA256:SHA256:3"; do
  IFS=: read -r name cipher digest mode <<< "$spec"
  g --passphrase "$PW" --s2k-cipher-algo "$cipher" --s2k-digest-algo "$digest" --s2k-mode "$mode" --quick-generate-key "Corpus $name <$name@corpus.invalid>" ed25519 sign never 2>/dev/null || continue
  fpr=$(g --list-keys --with-colons "Corpus $name" | awk -F: '/^fpr/ {print $10; exit}')
  g --passphrase "$PW" --s2k-cipher-algo "$cipher" --s2k-digest-algo "$digest" --s2k-mode "$mode" --quick-add-key "$fpr" cv25519 encr never >/dev/null 2>&1
  export_key "$name" "$fpr" "$PW"
  FPR[$name]=$fpr
done

# A stub primary key ("GNU dummy"), as `--export-secret-subkeys` writes it.
if [ -n "${FPR[ed25519]:-}" ]; then
  g --passphrase '' --export-secret-subkeys "${FPR[ed25519]}" > "$dest/keys/stub-primary.pgp" 2>/dev/null
  g --passphrase '' --armor --export-secret-subkeys "${FPR[ed25519]}" > "$dest/keys/stub-primary.asc" 2>/dev/null
  cp "$dest/certs/ed25519.fpr" "$dest/keys/stub-primary.fpr"
fi

# A key with several User IDs, a User Attribute-free certification by another key, an expiry and a revocation.
if [ -n "${FPR[ed25519]:-}" ] && [ -n "${FPR[rsa3072]:-}" ]; then
  f=${FPR[ed25519]}
  g --passphrase '' --quick-add-uid "$f" "Second <second@corpus.invalid>" >/dev/null 2>&1
  g --passphrase '' --quick-add-uid "$f" "Third <third@corpus.invalid>" >/dev/null 2>&1
  g --passphrase '' --quick-set-primary-uid "$f" "Second <second@corpus.invalid>" >/dev/null 2>&1
  g --passphrase '' --quick-set-expire "$f" 2y '*' >/dev/null 2>&1
  g --passphrase '' --default-key "${FPR[rsa3072]}" --quick-sign-key "$f" "Third <third@corpus.invalid>" >/dev/null 2>&1
  g --passphrase '' --quick-revoke-uid "$f" "Third <third@corpus.invalid>" >/dev/null 2>&1
  export_key multi-uid "$f" ""
  g --passphrase '' --command-fd 0 --gen-revoke --output "$dest/sigs/revocation-cert.asc" "$f" <<< $'y\n0\n\ny\n' >/dev/null 2>&1
  g --dearmor < "$dest/sigs/revocation-cert.asc" > "$dest/sigs/revocation-cert.pgp" 2>/dev/null
fi

# Signatures and messages, from keys that exist.
echo "corpus sample data for $LABEL" > "$home/data.txt"
head -c 300000 /dev/urandom > "$home/data.bin"
signer=${FPR[ed25519]:-${FPR[rsa3072]:-}}
if [ -n "$signer" ]; then
  g --passphrase '' -u "$signer" --detach-sign < "$home/data.txt" > "$dest/sigs/detached.pgp"
  g --passphrase '' -u "$signer" --armor --detach-sign < "$home/data.txt" > "$dest/sigs/detached.asc"
  g --passphrase '' -u "$signer" --sign < "$home/data.txt" > "$dest/messages/signed-inline.pgp"
  g --passphrase '' -u "$signer" --armor --sign < "$home/data.txt" > "$dest/messages/signed-inline.asc"
  g --passphrase '' -u "$signer" --clearsign < "$home/data.txt" > "$dest/messages/clearsigned.asc"
  g --passphrase '' -u "$signer" --textmode --armor --detach-sign < "$home/data.txt" > "$dest/sigs/detached-text.asc"
  g --passphrase '' -u "$signer" --sign --set-filename "name with spaces.bin" < "$home/data.bin" > "$dest/messages/signed-large.pgp"
  g --passphrase '' -u "$signer" --sign --compress-algo none < "$home/data.txt" > "$dest/messages/signed-nocompress.pgp"
  [ -n "${FPR[rsa3072]:-}" ] && g --passphrase '' -u "$signer" -u "${FPR[rsa3072]}" --sign < "$home/data.txt" > "$dest/messages/signed-two-signers.pgp"
fi
for name in rsa3072 ed25519 p256 bp256 ed448 kyber768; do
  [ -n "${FPR[$name]:-}" ] || continue
  g -r "${FPR[$name]}" --trust-model always -e < "$home/data.txt" > "$dest/messages/enc-$name.pgp" 2>/dev/null
  g -r "${FPR[$name]}" --trust-model always --armor -e < "$home/data.txt" > "$dest/messages/enc-$name.asc" 2>/dev/null
done
if [ -n "${FPR[ed25519]:-}" ]; then
  g -r "${FPR[ed25519]}" --trust-model always -e --hidden-recipient "${FPR[ed25519]}" < "$home/data.txt" > "$dest/messages/enc-hidden.pgp" 2>/dev/null
  g -r "${FPR[ed25519]}" -r "${FPR[rsa3072]:-${FPR[ed25519]}}" --trust-model always --set-filename f.txt -e < "$home/data.bin" > "$dest/messages/enc-large-two-recipients.pgp" 2>/dev/null
  g -r "${FPR[ed25519]}" -u "${FPR[ed25519]}" --passphrase '' --trust-model always -se < "$home/data.txt" > "$dest/messages/enc-signed.pgp" 2>/dev/null
fi
for cipher in AES128 AES192 AES256 TWOFISH CAMELLIA128 CAMELLIA192 CAMELLIA256 3DES CAST5 BLOWFISH IDEA; do
  g --passphrase "$PW" --symmetric --cipher-algo "$cipher" --s2k-mode 3 --allow-old-cipher-algos < "$home/data.txt" > "$dest/messages/sym-$cipher.pgp" 2>/dev/null || rm -f "$dest/messages/sym-$cipher.pgp"
done
g --passphrase "$PW" --symmetric --s2k-mode 1 < "$home/data.txt" > "$dest/messages/sym-salted.pgp" 2>/dev/null
g --passphrase "$PW" --symmetric --s2k-mode 0 --allow-weak-key-signatures < "$home/data.txt" > "$dest/messages/sym-simple.pgp" 2>/dev/null || rm -f "$dest/messages/sym-simple.pgp"
g --passphrase "$PW" --symmetric --disable-mdc --allow-old-cipher-algos < "$home/data.txt" > "$dest/messages/sym-no-mdc.pgp" 2>/dev/null || rm -f "$dest/messages/sym-no-mdc.pgp"
for z in zip zlib bzip2; do
  g --passphrase "$PW" --symmetric --compress-algo $z < "$home/data.txt" > "$dest/messages/sym-$z.pgp" 2>/dev/null || rm -f "$dest/messages/sym-$z.pgp"
done
for aead in ocb eax; do
  g --passphrase "$PW" --symmetric --force-aead --aead-algo "$aead" < "$home/data.txt" > "$dest/messages/sym-aead-$aead.pgp" 2>/dev/null || rm -f "$dest/messages/sym-aead-$aead.pgp"
done
g --passphrase "$PW" --symmetric --armor --set-filename "a.txt" < "$home/data.txt" > "$dest/messages/sym-named.asc" 2>/dev/null
g --passphrase "$PW" --symmetric < "$home/data.bin" > "$dest/messages/sym-large.pgp" 2>/dev/null

# Anything that came out empty was a failed command; drop it so the corpus holds only what GnuPG could make.
find "$dest" -type f -empty -delete
for d in keys certs sigs messages; do log "$d: $(find "$dest/$d" -type f ! -name '*.fpr' | wc -l) files"; done
