#!/usr/bin/env bash
# Regenerates testdata/openpgp/librepgp from GnuPG (the binary on PATH, version recorded in VERSION), with throwaway keys:
#   v5-*.gpg      a version 5 key (Ed25519 with a Curve25519 subkey) and v4o-*.gpg a version 4 key announcing OCB Encrypted Data
#   msg-*-ocbed.gpg   messages GnuPG encrypts to them (OCB Encrypted Data) and msg-pw-ocbed.gpg with a password (SKESK version 5)
#   msg-bzip2.gpg a password message with bzip2 compression
# With GnuPG 2.5 and ONECRYPTO_KYBER=1 it also writes the Kyber composite keys and messages (sec-/pub-/msg-kyber-*).
# Usage: tools/oracles/librepgp-fixtures.sh   (PATH and LD_LIBRARY_PATH select the GnuPG)
set -euo pipefail
out="$(cd "$(dirname "$0")/../.." && pwd)/testdata/openpgp/librepgp"
mkdir -p "$out"
home=$(mktemp -d); chmod 700 "$home"; export GNUPGHOME="$home"
text='librepgp test'

fpr() { gpg --batch --list-keys --with-colons "$1" | awk -F: '/^fpr/{print $10; exit}'; }

# A version 5 key needs --compliance=gnupg; it announces features 07 (MDC, OCB Encrypted Data, version 5).
gpg --batch --compliance=gnupg --passphrase '' --quick-gen-key v5@example.org ed25519/v5 sign,cert never
gpg --batch --compliance=gnupg --passphrase '' --quick-add-key "$(fpr v5@example.org)" cv25519/v5 encr never
gpg --batch --export v5@example.org > "$out/v5-pub.gpg"
gpg --batch --export-secret-keys v5@example.org > "$out/v5-sec.gpg"

# A version 4 key with OCB in its features (--rfc4880bis).
gpg --batch --compliance=gnupg --rfc4880bis --passphrase '' --quick-gen-key v4o@example.org ed25519 sign,cert never
gpg --batch --compliance=gnupg --rfc4880bis --passphrase '' --quick-add-key "$(fpr v4o@example.org)" cv25519 encr never
gpg --batch --export v4o@example.org > "$out/v4o-pub.gpg"
gpg --batch --export-secret-keys v4o@example.org > "$out/v4o-sec.gpg"

# A plain version 4 key (features: MDC only).
gpg --batch --passphrase '' --quick-gen-key v4@example.org ed25519 sign,cert never
gpg --batch --passphrase '' --quick-add-key "$(fpr v4@example.org)" cv25519 encr never
gpg --batch --export v4@example.org > "$out/v4-pub.gpg"
gpg --batch --export-secret-keys v4@example.org > "$out/v4-sec.gpg"

for k in v5 v4o; do
  echo "$text" | gpg --batch --yes --trust-model always --force-ocb -r "$k@example.org" -e --compress-algo none -o "$out/msg-$k-ocbed.gpg"
done
echo "$text" | gpg --batch --yes --pinentry-mode loopback --passphrase pw --symmetric --force-ocb --compress-algo none -o "$out/msg-pw-ocbed.gpg"
echo "$text" | gpg --batch --yes --pinentry-mode loopback --passphrase pw --symmetric --compress-algo bzip2 -o "$out/msg-bzip2.gpg"

if [ "${ONECRYPTO_KYBER:-0}" = 1 ]; then
  for a in ky768_cv25519 ky1024_cv448 ky768_nistp256 ky768_bp256; do
    gpg --batch --passphrase '' --quick-gen-key "k-$a@example.org" ed25519 sign,cert never
    gpg --batch --passphrase '' --quick-add-key "$(fpr "k-$a@example.org")" "$a" encr never
    echo "plain $a" | gpg --batch --yes --trust-model always -r "k-$a@example.org" -e -o "$out/msg-kyber-$a.gpg"
    gpg --batch --export "k-$a@example.org" > "$out/pub-kyber-$a.gpg"
    gpg --batch --export-secret-keys "k-$a@example.org" > "$out/sec-kyber-$a.gpg"
  done
fi
{ gpg --version | head -1; } > "$out/VERSION"
gpgconf --kill all || true; rm -rf "$home"
