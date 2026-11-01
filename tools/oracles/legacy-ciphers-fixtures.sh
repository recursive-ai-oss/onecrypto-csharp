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
gpg --version | head -1 > "$out/VERSION"
gpgconf --kill all || true; rm -rf "$home"
