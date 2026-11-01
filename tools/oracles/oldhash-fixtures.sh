#!/usr/bin/env bash
# Regenerates testdata/openpgp/oldhash from GnuPG (the binary on PATH), with a throwaway RSA key: detached and inline signatures made with
# SHA-224 and RIPEMD-160, and password messages whose string-to-key uses them. Our code only verifies and decrypts these.
set -euo pipefail
out="$(cd "$(dirname "$0")/../.." && pwd)/testdata/openpgp/oldhash"
mkdir -p "$out"
home=$(mktemp -d); chmod 700 "$home"; export GNUPGHOME="$home"
printf 'old hash test\n' > "$out/data.txt"
gpg --batch --passphrase '' --quick-gen-key oldhash@example.org rsa2048 sign,cert never
gpg --batch --export oldhash@example.org > "$out/rsa-pub.gpg"
for h in SHA224 RIPEMD160; do
  l=$(echo "$h" | tr A-Z a-z)
  gpg --batch --yes --allow-weak-digest-algos --digest-algo "$h" --detach-sign -o "$out/detached-$l.sig" "$out/data.txt"
  gpg --batch --yes --allow-weak-digest-algos --digest-algo "$h" --sign --compress-algo none -o "$out/inline-$l.gpg" "$out/data.txt"
  gpg --batch --yes --pinentry-mode loopback --passphrase pw --symmetric --s2k-mode 3 --s2k-digest-algo "$h" --compress-algo none -o "$out/pw-$l.gpg" "$out/data.txt"
done
gpgconf --kill all || true
