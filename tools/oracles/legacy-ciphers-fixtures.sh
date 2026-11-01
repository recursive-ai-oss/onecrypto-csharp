#!/usr/bin/env bash
# Regenerates testdata/openpgp/legacy/*.gpg: SEIPD v1 messages under password "pw" for the legacy ciphers,
# written by GnuPG (version recorded in testdata/openpgp/legacy/VERSION). Plaintext is "legacy cipher test <NAME>\n".
set -euo pipefail
out="$(cd "$(dirname "$0")/../.." && pwd)/testdata/openpgp/legacy"
home=$(mktemp -d); chmod 700 "$home"; export GNUPGHOME="$home"
for c in CAST5 3DES BLOWFISH IDEA TWOFISH CAMELLIA128 CAMELLIA256; do
  echo "legacy cipher test $c" | gpg --batch --yes --allow-old-cipher-algos --pinentry-mode loopback --passphrase pw \
    --symmetric --cipher-algo "$c" --s2k-cipher-algo "$c" --compress-algo none -o "$out/msg-$c.gpg"
done
# Old Symmetrically Encrypted Data (no integrity protection), plaintext "sed test\n" and "sed test cast\n".
echo 'sed test' | gpg --batch --yes --allow-old-cipher-algos --pinentry-mode loopback --passphrase pw --symmetric --rfc2440 --disable-mdc \
  --cipher-algo AES256 --compress-algo none -o "$out/sed-aes.gpg"
echo 'sed test cast' | gpg --batch --yes --allow-old-cipher-algos --pinentry-mode loopback --passphrase pw --symmetric --rfc2440 --disable-mdc \
  --cipher-algo CAST5 --s2k-cipher-algo CAST5 --compress-algo none -o "$out/sed-cast5.gpg"
gpg --version | head -1 > "$out/VERSION"
gpgconf --kill all || true; rm -rf "$home"
# LibrePGP: SKESK v5 and OCB Encrypted Data (tag 20) from GnuPG (plaintext "ocbed test\n").
home=$(mktemp -d); chmod 700 "$home"; export GNUPGHOME="$home"
echo 'ocbed test' | gpg --batch --yes --pinentry-mode loopback --passphrase pw --symmetric --force-ocb --compress-algo none -o "$out/ocbed-librepgp.gpg"
gpgconf --kill all || true; rm -rf "$home"
