#!/usr/bin/env bash
# Writes the fixtures the browser suite parses and verifies into testdata/browser/ with the openssl on PATH (the version used is
# recorded in testdata/browser/VERSION). Every key is generated here for the fixtures and is worth nothing; the passphrase of
# the protected files is "password".
#
#   tools/gen-browser-fixtures.sh [output dir]
set -euo pipefail
here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
out="${1:-$here/testdata/browser}"
work="$(mktemp -d "${TMPDIR:-/tmp}/browser-fixtures.XXXXXX")"
trap 'rm -rf "$work"' EXIT
mkdir -p "$out"
cd "$work"
O=openssl
days=36500

# One CA and leaves of each key type. The subjects say what they are for.
$O ecparam -name prime256v1 -genkey -noout -out ca.key
$O req -x509 -new -key ca.key -sha256 -days $days -subj "/CN=Browser Fixture CA" \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -out ca.pem

leaf() { # name, key args..., extra extensions
  local name=$1; shift
  local ext=$1; shift
  "$@" > "$name.key" 2>/dev/null
  $O req -new -key "$name.key" -subj "/CN=Browser Fixture $name" -out "$name.csr"
  printf '%s\n' "$ext" > "$name.ext"
  $O x509 -req -in "$name.csr" -CA ca.pem -CAkey ca.key -CAcreateserial -days $days -sha256 -extfile "$name.ext" -out "$name.pem" 2>/dev/null
}
sign_ext="basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=emailProtection"
leaf rsa "$sign_ext" $O genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048
leaf p256 "$sign_ext" $O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256
leaf p384 "$sign_ext" $O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-384
leaf p521 "$sign_ext" $O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-521
leaf ed25519 "$sign_ext" $O genpkey -algorithm ED25519
leaf tsa "basicConstraints=CA:FALSE
keyUsage=digitalSignature
extendedKeyUsage=critical,timeStamping" $O genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256

printf 'browser fixture content\n' > content.txt

# CMS SignedData: the signer certificate travels inside, the content is attached.
cms() { $O cms -sign -binary -nodetach -in content.txt -signer "$2.pem" -inkey "$2.key" -certfile ca.pem -outform DER $3 -out "$1.der"; }
cms cms-rsa-pkcs1 rsa "-md sha256"
cms cms-rsa-pss rsa "-md sha256 -keyopt rsa_padding_mode:pss"
cms cms-p256 p256 "-md sha256"
cms cms-p384 p384 "-md sha384"
cms cms-p521 p521 "-md sha512"
cms cms-ed25519 ed25519 "-md sha512"

# RFC 3161: a request and the authority's answer.
$O ts -query -data content.txt -sha256 -cert -no_nonce -out ts.tsq
cat > tsa.cnf <<EOF
[tsa]
default_tsa = tsa_config
[tsa_config]
serial = tsa.serial
signer_cert = tsa.pem
certs = ca.pem
signer_key = tsa.key
signer_digest = sha256
default_policy = 1.2.3.4.5
digests = sha256
crypto_device = builtin
EOF
echo 01 > tsa.serial
$O ts -reply -config tsa.cnf -queryfile ts.tsq -out ts.tsr 2>/dev/null

# OCSP: a good answer and a revoked one from the CA itself.
: > index.txt
serial_hex=$($O x509 -in p256.pem -noout -serial | cut -d= -f2)
printf 'V\t21260101000000Z\t\t%s\tunknown\t/CN=Browser Fixture p256\n' "$serial_hex" > index.txt
$O ocsp -issuer ca.pem -cert p256.pem -reqout ocsp.req -no_nonce
$O ocsp -index index.txt -CA ca.pem -rsigner ca.pem -rkey ca.key -reqin ocsp.req -respout ocsp-good.der -ndays 36500 2>/dev/null
printf 'R\t21260101000000Z\t260101000000Z,keyCompromise\t%s\tunknown\t/CN=Browser Fixture p256\n' "$serial_hex" > index.txt
$O ocsp -index index.txt -CA ca.pem -rsigner ca.pem -rkey ca.key -reqin ocsp.req -respout ocsp-revoked.der -ndays 36500 2>/dev/null

# CRL with one revoked certificate.
mkdir -p ca.db; echo 01 > ca.db/crlnumber
printf 'R\t21260101000000Z\t260101000000Z,keyCompromise\t%s\tunknown\t/CN=Browser Fixture p256\n' "$serial_hex" > ca.db/index.txt
cat > ca.cnf <<EOF
[ca]
default_ca = c
[c]
database = ca.db/index.txt
crlnumber = ca.db/crlnumber
default_md = sha256
default_crl_days = 36500
EOF
$O ca -config ca.cnf -cert ca.pem -keyfile ca.key -gencrl -out crl.pem </dev/null 2>/dev/null

# Private keys: plain, protected with PBKDF2 and AES, and PKCS #12 files without, with and with legacy password-based encryption.
$O pkcs8 -topk8 -nocrypt -in ed25519.key -out pk8-ed25519.pem
$O pkcs8 -topk8 -nocrypt -in p256.key -out pk8-p256.pem
$O pkcs8 -topk8 -v2 aes-256-cbc -passout pass:password -in p256.key -out pk8-p256-pbes2.pem
$O pkcs12 -export -inkey p256.key -in p256.pem -certfile ca.pem -keypbe NONE -certpbe NONE -nomac -passout pass: -out p12-plain.p12
$O pkcs12 -export -inkey p256.key -in p256.pem -certfile ca.pem -passout pass:password -out p12-pbes2.p12
$O pkcs12 -export -legacy -inkey p256.key -in p256.pem -certfile ca.pem -passout pass:password -out p12-legacy.p12 \
  || echo "no legacy provider: p12-legacy.p12 not written" >&2

# OpenSSH keys: public lines and unprotected private files, with ssh-keygen.
for t in ed25519 rsa ecdsa; do
  bits=""; [ "$t" = rsa ] && bits="-b 2048"; [ "$t" = ecdsa ] && bits="-b 256"
  ssh-keygen -q -t $t $bits -N "" -C "browser fixture $t" -f "ssh-$t" </dev/null
done

for f in ssh-ed25519 ssh-rsa ssh-ecdsa; do cp "$f" "$out/$f.key"; cp "$f.pub" "$out/$f.pub"; done
for f in ca.pem rsa.pem p256.pem p384.pem p521.pem ed25519.pem tsa.pem crl.pem pk8-*.pem; do cp "$f" "$out/${f/#ca.pem/ca-cert.pem}"; done
for f in cms-*.der ts.tsq ts.tsr ocsp-good.der ocsp-revoked.der p12-*.p12; do [ -f "$f" ] && cp "$f" "$out/"; done
cp content.txt "$out/content.txt"
$O version > "$out/VERSION"
ls "$out" | wc -l
