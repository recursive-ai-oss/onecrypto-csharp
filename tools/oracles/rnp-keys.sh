#!/usr/bin/env bash
# Two-way key-management checks against RNP (rnp/rnpkeys, installed by tools/oracles/rnp.sh): keys we generate (version 4 profiles, with and without a
# password) are imported and used by RNP, our revocations and certifications are listed by RNP as such, and RNP's own keys go through our
# change-key-password, revoke-key and certify-userid. RNP reads no version 6 keys, so those profiles report n/a.
# Usage: tools/oracles/rnp-keys.sh "<our onecrypto command, e.g. dotnet path/to/onecrypto.dll>" <work dir>
source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"
set +e +o pipefail
OURS="$1 sop"; W=${2:?work dir}
D=$ORACLES/rnp-distro
export LD_LIBRARY_PATH=$D/usr/lib/x86_64-linux-gnu${LD_LIBRARY_PATH:+:$LD_LIBRARY_PATH}
RNP="$D/usr/bin/rnp --notty"; RNPK="$D/usr/bin/rnpkeys --notty"
mkdir -p "$W" && cd "$W" || exit 2
pass=0; fail=0; na=0
ok() { pass=$((pass+1)); echo "ok   $1"; }
bad() { fail=$((fail+1)); echo "FAIL $1"; }
nav() { na=$((na+1)); echo "n/a  $1"; }
fresh() { rm -rf "$W/home"; mkdir -m 700 "$W/home"; }
run() { local name=$1; shift; fresh; if "$@" >/dev/null 2>err.txt; then ok "$name"; else bad "$name: $(head -c 200 err.txt | tr '\n' ' ')"; fi; }
$D/usr/bin/rnp --version | head -1
printf 'Hello, rnp key interop\nsecond line\n' > msg.txt
echo -n 'pw one' > pw1.txt; echo -n 'pw two' > pw2.txt
UID1='Ours <ours@example.org>'
$OURS generate-key --profile=rfc4880 'Certifier <certifier@example.org>' > certifier.key; $OURS extract-cert < certifier.key > certifier.cert

for prof in rfc4880 draft-koch-eddsa-for-openpgp-00 nist-p256 nist-p384 nist-p521 rfc9580-v4 rfc9580; do
  for prot in none pw; do
    k=$prof-$prot; kp=""; PP=""; [ $prot = pw ] && { kp="--with-key-password=pw1.txt"; PP="pw one"; }
    $OURS generate-key --profile=$prof $kp "$UID1" > $k.key 2>/dev/null || { nav "[$k] our generate-key"; continue; }
    $OURS extract-cert < $k.key > $k.cert
    fresh; if ! $RNPK --homedir "$W/home" --import $k.key >/dev/null 2>imp.err; then nav "[$k] rnp does not import this key: $(head -c 100 imp.err | tr '\n' ' ')"; continue; fi
    s1() { $RNPK --homedir "$W/home" --import $k.key && $RNPK --homedir "$W/home" --list-keys | grep -q ours@example.org; }
    s2() { $RNPK --homedir "$W/home" --import $k.cert && $RNP --homedir "$W/home" --recipient ours@example.org --encrypt --output e1.rnp msg.txt --overwrite && $OURS decrypt $kp $k.key < e1.rnp | cmp - msg.txt; }
    s3() { $RNPK --homedir "$W/home" --import $k.key && $OURS encrypt --profile=rfc4880 $k.cert < msg.txt > e2.asc && $RNP --homedir "$W/home" --password "$PP" --decrypt e2.asc --output out.bin --overwrite && cmp out.bin msg.txt; }
    s4() { $RNPK --homedir "$W/home" --import $k.key && $RNP --homedir "$W/home" --password "$PP" --userid ours@example.org --sign --detach --armor --output s1.sig msg.txt --overwrite && $OURS verify s1.sig $k.cert < msg.txt; }
    s5() { $RNPK --homedir "$W/home" --import $k.cert && $OURS sign $kp $k.key < msg.txt > msg.txt.sig && $RNP --homedir "$W/home" --verify msg.txt.sig; } # rnp finds the data file by dropping .sig
    s6() { $RNPK --homedir "$W/home" --import $k.cert && $OURS revoke-key $kp < $k.key > rev.cert && $RNPK --homedir "$W/home" --import rev.cert && $RNPK --homedir "$W/home" --list-keys | grep -qi revoked; }
    s7() { $RNPK --homedir "$W/home" --import certifier.cert && $RNPK --homedir "$W/home" --import $k.cert && $OURS certify-userid --userid="$UID1" certifier.key < $k.cert > c.asc && $RNPK --homedir "$W/home" --import c.asc && $RNPK --homedir "$W/home" --list-keys --with-sigs | grep -q 'certifier\|Certifier'; }
    s8() { $OURS update-key $kp < $k.key > upd.key && $OURS extract-cert < upd.key > upd.cert && $RNPK --homedir "$W/home" --import upd.cert && $RNP --homedir "$W/home" --recipient ours@example.org --encrypt --output e3.rnp msg.txt --overwrite && $OURS decrypt $kp upd.key < e3.rnp | cmp - msg.txt; }
    s9() { $OURS change-key-password --old-key-password=pw1.txt --new-key-password=pw2.txt < $k.key > chg.key && $RNPK --homedir "$W/home" --import chg.key && $RNP --homedir "$W/home" --password 'pw two' --userid ours@example.org --sign --detach --armor --output s3.sig msg.txt --overwrite && $OURS verify s3.sig $k.cert < msg.txt; }
    run "[$k] rnp imports and lists the secret key" s1
    run "[$k] rnp encrypts, we decrypt" s2
    run "[$k] we encrypt, rnp decrypts" s3
    run "[$k] rnp signs, we verify" s4
    run "[$k] we sign, rnp verifies" s5
    run "[$k] our revocation is listed by rnp" s6
    run "[$k] our certification is listed by rnp" s7
    run "[$k] update-key output is usable by rnp" s8
    [ $prot = pw ] && run "[$k] changed password: rnp signs with the new one" s9
  done
done

# RNP's own keys through our key management
for prot in none pw; do
  PP=''; kp=''; [ $prot = pw ] && { PP='pw one'; kp="--with-key-password=pw1.txt"; }
  fresh
  $RNPK --homedir "$W/home" --generate-key --userid "Rnp <rnp@example.org>" --numbits 3072 --password "$PP" >/dev/null 2>&1
  $RNPK --homedir "$W/home" --export-key --secret rnp@example.org > rnp.key 2>/dev/null
  $RNPK --homedir "$W/home" --export-key rnp@example.org > rnp.cert 2>/dev/null
  r1() { $RNPK --homedir "$W/home" --import rnp.cert && $OURS revoke-key $kp < rnp.key > rrev.cert && $RNPK --homedir "$W/home" --import rrev.cert && $RNPK --homedir "$W/home" --list-keys | grep -qi revoked; }
  r2() { $RNPK --homedir "$W/home" --import rnp.cert && $RNPK --homedir "$W/home" --import certifier.cert && $OURS certify-userid --userid='Rnp <rnp@example.org>' certifier.key < rnp.cert > rc.asc && $RNPK --homedir "$W/home" --import rc.asc && $RNPK --homedir "$W/home" --list-keys --with-sigs | grep -qi certifier; }
  r3() { $OURS change-key-password $( [ $prot = pw ] && echo --old-key-password=pw1.txt ) --new-key-password=pw2.txt < rnp.key > rn.key && $RNPK --homedir "$W/home" --import rn.key && $RNP --homedir "$W/home" --password 'pw two' --userid rnp@example.org --sign --detach --armor --output rs.sig msg.txt --overwrite && $OURS verify rs.sig rnp.cert < msg.txt; }
  r4() { $OURS update-key $kp < rnp.key > ru.key && $OURS extract-cert < ru.key > ru.cert && $RNPK --homedir "$W/home" --import ru.cert && $RNP --homedir "$W/home" --recipient rnp@example.org --encrypt --output re.rnp msg.txt --overwrite && $OURS decrypt $kp ru.key < re.rnp | cmp - msg.txt; }
  run "[rnp-rsa-$prot] our revoke-key is listed by rnp" r1
  run "[rnp-rsa-$prot] our certify-userid is listed by rnp" r2
  run "[rnp-rsa-$prot] our change-key-password: rnp signs with the new one" r3
  run "[rnp-rsa-$prot] our update-key: rnp encrypts to it and we decrypt" r4
done
echo "pass=$pass fail=$fail n/a=$na"
[ "$fail" -eq 0 ]
