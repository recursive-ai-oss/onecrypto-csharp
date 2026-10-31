#!/usr/bin/env bash
# Writes passphrase-protected OpenSSH test keys to testdata/bcrypt-pbkdf/. They are generated test keys with throwaway
# passphrases (the file name carries the cipher, rounds and passphrase). The tests derive the cipher key and IV with our
# bcrypt-pbkdf and must decrypt the private section, so ssh-keygen is the oracle for the construction.
# Needs ssh-keygen; the version used is recorded in testdata/bcrypt-pbkdf/VERSION.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")/.."
out=testdata/bcrypt-pbkdf
mkdir -p "$out"
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
ssh -V 2>&1 | head -1 > "$out/VERSION"
gen() { # cipher rounds passphrase type
  local f="$work/k"
  rm -f "$f" "$f.pub"
  ssh-keygen -q -t "$4" -Z "$1" -a "$2" -N "$3" -C "test key, not for use" -f "$f"
  cp "$f" "$out/$4-$1-a$2-$(printf %s "$3" | tr -c 'A-Za-z0-9' _).key"
}
gen aes256-ctr 16 "correct horse" ed25519
gen aes256-ctr 1 "x" ed25519
gen aes128-ctr 8 "battery staple" ed25519
gen aes256-ctr 64 "pässwörd" ed25519
gen aes256-cbc 5 "longer passphrase with spaces and a very long tail 0123456789" ecdsa
ls "$out"
