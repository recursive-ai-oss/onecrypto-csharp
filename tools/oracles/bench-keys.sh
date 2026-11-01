#!/usr/bin/env bash
# Regenerates the throwaway test keys used by the OpenPGP benchmark rows (testdata/openpgp/keys): version 4 RSA-3072 and
# Ed25519/Curve25519 certificates with unprotected secret keys, made by GnuPG. They protect nothing.
set -euo pipefail
out="$(cd "$(dirname "$0")/../.." && pwd)/testdata/openpgp/keys"
home=$(mktemp -d); chmod 700 "$home"; export GNUPGHOME="$home"
for spec in "rsa3072:rsa3072" "ed25519:cv25519"; do
  s=${spec%%:*}; e=${spec##*:}
  gpg --batch --quiet --passphrase '' --quick-gen-key "test-$s <test-$s@example.org>" "$s" sign,cert never
  fpr=$(gpg --batch --list-keys --with-colons "test-$s@example.org" | awk -F: '/^fpr/{print $10; exit}')
  gpg --batch --quiet --passphrase '' --quick-add-key "$fpr" "$e" encr never
  gpg --batch --armor --export "$fpr" > "$out/test-$s.pub.asc"
  gpg --batch --armor --pinentry-mode loopback --passphrase '' --export-secret-keys "$fpr" > "$out/test-$s.sec.asc"
done
gpg --version | head -1 > "$out/VERSION"
gpgconf --kill all || true; rm -rf "$home"
