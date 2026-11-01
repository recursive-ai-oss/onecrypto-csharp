#!/usr/bin/env bash
# Two-way smoke test against RNP (rnp/rnpkeys, installed by tools/oracles/rnp.sh): keys made by rnpkeys (RSA) and by GnuPG (Ed25519 and
# Curve25519, imported into RNP), then sign/verify (detached, inline, cleartext) and encrypt/decrypt in both directions through our sop.
# RNP does not read RFC 9580 version 6 keys or SEIPD v2, so ours-to-RNP uses the rfc4880 profile; RNP's own AEAD packet (LibrePGP OCB) is read by us.
# Usage: tools/oracles/rnp-messages.sh <"dotnet path/to/onecrypto.dll"> <work dir>
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
set +e +o pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
SOP=${1:?sop command}
W=${2:?work dir}
D=$ORACLES/rnp-distro
export LD_LIBRARY_PATH=$D/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
RNP="$D/usr/bin/rnp --notty"; RNPK="$D/usr/bin/rnpkeys --notty"
mkdir -p "$W" && cd "$W" || exit 2
sop() { $SOP sop "$@"; }
pass=0; fail=0; unsup=0
ok() { pass=$((pass+1)); echo "ok   $1"; }
bad() { fail=$((fail+1)); echo "FAIL $1"; }
skip() { unsup=$((unsup+1)); echo "skip $1"; }
$D/usr/bin/rnp --version | head -1
printf 'Hello from the oracle test\nsecond line\n' > msg.txt
head -c 300000 /dev/urandom > big.bin

# --- keys: RNP-generated RSA, and the GnuPG-made test keys imported into RNP
H=$W/rnphome; rm -rf "$H"; mkdir -m 700 "$H"
$RNPK --homedir "$H" --generate-key --userid "rnp-rsa <rnp-rsa@example.org>" --numbits 3072 --password '' >/dev/null 2>&1
$RNPK --homedir "$H" --export-key --secret rnp-rsa@example.org > rnp-rsa.key 2>/dev/null
$RNPK --homedir "$H" --export-key rnp-rsa@example.org > rnp-rsa.cert 2>/dev/null
for k in rsa3072 ed25519; do
  $RNPK --homedir "$H" --import "$root/testdata/openpgp/keys/test-$k.sec.asc" >/dev/null 2>&1
  cp "$root/testdata/openpgp/keys/test-$k.sec.asc" "$k.key"; cp "$root/testdata/openpgp/keys/test-$k.pub.asc" "$k.cert"
done
ls -la rnp-rsa.key rnp-rsa.cert | awk '{print $5, $9}'

for name in rnp-rsa rsa3072 ed25519; do
  uid=$name@example.org; [ "$name" != rnp-rsa ] && uid=test-$name@example.org
  # RNP -> ours
  $RNP --homedir "$H" --password '' --userid "$uid" --sign --detach --armor --output $name.rsig msg.txt --overwrite >/dev/null 2>&1
  sop verify $name.rsig $name.cert < msg.txt >/dev/null && ok "$name verify rnp detached" || bad "$name verify rnp detached"
  $RNP --homedir "$H" --password '' --userid "$uid" --sign --output $name.rsigned big.bin --overwrite >/dev/null 2>&1
  sop inline-verify $name.cert < $name.rsigned > out.bin && cmp -s out.bin big.bin && ok "$name inline-verify rnp" || bad "$name inline-verify rnp"
  $RNP --homedir "$H" --password '' --userid "$uid" --clearsign --output $name.rclear msg.txt --overwrite >/dev/null 2>&1
  sop inline-verify $name.cert < $name.rclear >/dev/null && ok "$name inline-verify rnp cleartext" || bad "$name inline-verify rnp cleartext"
  for opt in "" "--cipher CAMELLIA256" "--cipher TWOFISH" "--cipher AES128 --zlib" "--cipher AES256 --zip -z 6" "--aead=OCB" "--aead=EAX"; do
    $RNP --homedir "$H" --recipient "$uid" --encrypt $opt --output $name.renc big.bin --overwrite >/dev/null 2>&1
    sop decrypt $name.key < $name.renc > dec.bin 2>/dev/null && cmp -s dec.bin big.bin && ok "$name decrypt rnp [$opt]" || bad "$name decrypt rnp [$opt]"
  done
  $RNP --homedir "$H" --recipient "$uid" --userid "$uid" --password '' --sign --encrypt --output $name.rencs big.bin --overwrite >/dev/null 2>&1
  sop decrypt --verify-with=$name.cert --verifications-out=$name.v $name.key < $name.rencs > dec.bin 2>/dev/null && cmp -s dec.bin big.bin && [ -s $name.v ] && ok "$name decrypt+verify rnp sign+encrypt" || bad "$name decrypt+verify rnp sign+encrypt"
  # ours -> RNP
  sop sign $name.key < msg.txt > $name.osig
  $RNP --homedir "$H" --verify $name.osig --source msg.txt >/dev/null 2>&1 && ok "$name rnp verifies our detached" || bad "$name rnp verifies our detached"
  sop inline-sign $name.key < big.bin > $name.osigned
  $RNP --homedir "$H" --decrypt $name.osigned --output dec.bin --overwrite >/dev/null 2>&1 && cmp -s dec.bin big.bin && ok "$name rnp verifies our inline" || bad "$name rnp verifies our inline"
  sop inline-sign --as=clearsigned $name.key < msg.txt > $name.oclear
  $RNP --homedir "$H" --verify $name.oclear >/dev/null 2>&1 && ok "$name rnp verifies our cleartext" || bad "$name rnp verifies our cleartext"
  sop encrypt --profile=rfc4880 --sign-with=$name.key $name.cert < big.bin > $name.oenc
  $RNP --homedir "$H" --password '' --decrypt $name.oenc --output dec.bin --overwrite >/dev/null 2>&1 && cmp -s dec.bin big.bin && ok "$name rnp decrypts ours (rfc4880, signed)" || bad "$name rnp decrypts ours (rfc4880, signed)"
done

# --- passwords
for opt in "" "--cipher CAMELLIA256" "--cipher TWOFISH" "--cipher CAST5" "--cipher 3DES" "--cipher IDEA" "--cipher BLOWFISH" "--aead=OCB"; do
  $RNP --homedir "$H" --password pw --symmetric $opt --output pw.renc big.bin --overwrite >/dev/null 2>&1
  printf pw > pw.txt
  sop decrypt --with-password=pw.txt < pw.renc > dec.bin 2>/dev/null && cmp -s dec.bin big.bin && ok "password decrypt rnp [$opt]" || bad "password decrypt rnp [$opt]"
done
sop encrypt --profile=rfc4880 --with-password=pw.txt < big.bin > pw.oenc
$RNP --homedir "$H" --password pw --decrypt pw.oenc --output dec.bin --overwrite >/dev/null 2>&1 && cmp -s dec.bin big.bin && ok "rnp decrypts our password message" || bad "rnp decrypts our password message"
echo "rnp: $pass ok, $fail failed, $unsup skipped"
[ $fail -eq 0 ]
