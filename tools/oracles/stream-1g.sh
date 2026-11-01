#!/usr/bin/env bash
# Streams 1 GiB through our sop (encrypt to the RFC 9580 sample v6 certificate and decrypt with its key, SEIPD v2; inline sign/verify) and prints each step's peak resident set,
# to show that memory stays flat whatever the size.
# Usage: tools/oracles/stream-1g.sh <path to onecrypto.dll> <work dir (large, not RAM-backed)> [size in MiB, default 1024]
set -eu
DLL=${1:?onecrypto.dll}; W=${2:?work dir}; MIB=${3:-1024}
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
mkdir -p "$W"; cd "$W"
head -c $((MIB * 1048576)) /dev/urandom > in.bin
K="$root/testdata/openpgp"
sop() { /usr/bin/time -f "  peak %M KiB, %e s" dotnet "$DLL" sop "$@"; }
echo "encrypt (to a certificate)"; sop encrypt "$K/rfc9580/A_3.asc" < in.bin > enc.pgp
echo "decrypt"; sop decrypt "$K/rfc9580/A_4.asc" < enc.pgp | cmp - in.bin && echo "  round trip identical"
echo "inline-sign"; sop inline-sign "$K/keys/test-ed25519.sec.asc" --no-armor < in.bin > signed.pgp
echo "inline-verify"; sop inline-verify "$K/keys/test-ed25519.pub.asc" < signed.pgp | cmp - in.bin && echo "  round trip identical"
rm -f in.bin enc.pgp signed.pgp
