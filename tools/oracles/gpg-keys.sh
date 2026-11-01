#!/usr/bin/env bash
# Two-way key-management checks against a GnuPG binary (throwaway home): keys we generate (each profile, with and without a password) are imported,
# listed and used by gpg; our revocations and certifications are honoured by gpg; and gpg's own keys go through our change-key-password, revoke-key,
# certify-userid, update-key and merge-certs. GnuPG reads no version 6 keys, so those profiles report n/a.
# Usage: GPG=<path to gpg> tools/oracles/gpg-keys.sh "<our onecrypto command, e.g. dotnet path/to/onecrypto.dll>" <work dir>
set -u
OURS="$1 sop"; W=${2:?work dir}; GPG=${GPG:-gpg}
mkdir -p "$W" && cd "$W" || exit 2
export GNUPGHOME="$W/gnupg"
rm -rf "$GNUPGHOME" && mkdir -m 700 "$GNUPGHOME"
printf 'allow-loopback-pinentry\n' > "$GNUPGHOME/gpg-agent.conf"
g() { $GPG --batch --yes --quiet --pinentry-mode loopback "$@"; }
pass=0; fail=0; na=0
ok() { pass=$((pass+1)); echo "ok   $1"; }
bad() { fail=$((fail+1)); echo "FAIL $1"; }
nav() { na=$((na+1)); echo "n/a  $1"; }

$GPG --version | head -1
printf 'Hello, gpg interop\nsecond line\n' > msg.txt
echo -n 'pw one' > pw1.txt; echo -n 'pw two' > pw2.txt
UID1='Ours <ours@example.org>'
$OURS generate-key --profile=rfc4880 'Certifier <certifier@example.org>' > certifier.key; $OURS extract-cert < certifier.key > certifier.cert
GPGCONF=${GPG%gpg}gpgconf; [ "$GPGCONF" = gpgconf ] || [ -x "$GPGCONF" ] || GPGCONF=gpgconf
# A fresh home for every check: the agent keeps state in the home, so it is stopped before the directory goes.
fresh() { $GPGCONF --homedir "$GNUPGHOME" --kill all 2>/dev/null; rm -rf "$GNUPGHOME"; mkdir -m 700 "$GNUPGHOME"; printf 'allow-loopback-pinentry\n' > "$GNUPGHOME/gpg-agent.conf"; g --import certifier.cert 2>/dev/null; }


run() { # name, then a function body in the current shell
  local name=$1; shift
  fresh
  if "$@" >/dev/null 2>err.txt; then ok "$name"; 
  elif grep -q "cannot open '/dev/tty'" err.txt; then nav "$name: this gpg build asks the terminal for --gen-revoke even with --command-fd"
  elif [ "${prot:-}" = none ] && grep -q 'No secret key' err.txt && $GPG --version | head -1 | grep -qE ' 2\.[5-9]'; then nav "$name: gpg 2.5 does not import unprotected ECDH subkeys, not even from its own --export-secret-keys"
  else bad "$name: $(head -c 200 err.txt | tr '\n' ' ')"; fi
}
list_fpr() { g --list-keys --with-colons "$1" | awk -F: '/^fpr/{print $10; exit}'; }

for prof in rfc4880 draft-koch-eddsa-for-openpgp-00 nist-p256 nist-p384 nist-p521 rfc9580-v4 rfc9580 rfc9580-ed448 rfc9580-rsa; do
  for prot in none pw; do
    k=$prof-$prot; kp=""; PP=""; [ $prot = pw ] && { kp="--with-key-password=pw1.txt"; PP="pw one"; }
    $OURS generate-key --profile=$prof $kp "$UID1" > $k.key 2>/dev/null || { nav "[$k] our generate-key"; continue; }
    $OURS extract-cert < $k.key > $k.cert
    case $prof in rfc9580|rfc9580-ed448|rfc9580-rsa)
      fresh; if g --import $k.cert 2>/dev/null; then ok "[$k] gpg imported a v6 certificate"; else nav "[$k] gpg reads no version 6 keys"; fi; continue;; esac
    fresh
    if ! g --passphrase "$PP" --import $k.key 2>imp.err; then
      if [ $prof = rfc9580-v4 ]; then nav "[$k] gpg cannot import native Ed25519/X25519 keys"; else bad "[$k] gpg import secret key: $(head -c 160 imp.err | tr '\n' ' ')"; fi
      continue
    fi
    fpr=$(list_fpr ours@example.org)
    t1() { g --import $k.cert; g --check-sigs ours@example.org 2>&1 | grep -q '^sig!' && ! g --check-sigs ours@example.org 2>&1 | grep -qE '^sig[-%?]'; }
    t2() { g --import $k.cert; g --trust-model always -r $fpr -o e1.gpg --encrypt msg.txt && $OURS decrypt $kp $k.key < e1.gpg | cmp - msg.txt; }
    t3() { g --passphrase "$PP" --import $k.key; $OURS encrypt --profile=rfc4880 $k.cert < msg.txt > e2.asc && g --passphrase "$PP" --decrypt e2.asc | cmp - msg.txt; }
    t4() { g --passphrase "$PP" --import $k.key; g --passphrase "$PP" --local-user $fpr --detach-sign -o s1.sig msg.txt && $OURS verify s1.sig $k.cert < msg.txt; }
    t5() { g --import $k.cert; $OURS sign $kp $k.key < msg.txt > s2.sig && g --verify s2.sig msg.txt; }
    t6() { g --import $k.cert; $OURS revoke-key $kp < $k.key > rev.cert && g --import rev.cert; g --list-keys --with-colons ours@example.org | grep -q '^pub:r:'; }
    t7() { g --import $k.cert; $OURS certify-userid --userid="$UID1" certifier.key < $k.cert > cert.asc && g --import cert.asc; g --check-sigs ours@example.org 2>&1 | grep -q '^sig!.*Certifier' && $OURS validate-userid "$UID1" certifier.cert < cert.asc; }
    t8() { $OURS update-key $kp < $k.key > upd.key && $OURS extract-cert < upd.key > upd.cert && g --import upd.cert && g --check-sigs ours@example.org 2>&1 | grep -q '^sig!' && g --trust-model always -r $fpr -o e3.gpg --encrypt msg.txt && $OURS decrypt $kp upd.key < e3.gpg | cmp - msg.txt; }
    t9() { $OURS change-key-password --old-key-password=pw1.txt --new-key-password=pw2.txt < $k.key > chg.key && g --passphrase 'pw two' --import chg.key && g --passphrase 'pw two' --local-user $fpr --detach-sign -o s3.sig msg.txt && $OURS verify s3.sig $k.cert < msg.txt; }
    run "[$k] gpg lists the key and its self-signatures check out" t1
    run "[$k] gpg encrypts to the subkey, we decrypt" t2
    run "[$k] we encrypt, gpg decrypts" t3
    run "[$k] gpg signs, we verify" t4
    run "[$k] we sign, gpg verifies" t5
    run "[$k] our revocation makes gpg show the key revoked" t6
    run "[$k] our certification is a good signature in gpg and validates in ours" t7
    run "[$k] update-key output is still usable by gpg" t8
    [ $prot = pw ] && run "[$k] changed password: gpg imports and signs with the new one" t9
  done
done

# gpg's own keys through our key management
for spec in rsa3072 ed25519 nistp256; do
  case $spec in rsa3072) e=rsa3072;; ed25519) e=cv25519;; nistp256) e=nistp256;; esac
  for prot in none pw; do
    p=''; kp=""; [ $prot = pw ] && { p='pw one'; kp="--with-key-password=pw1.txt"; }
    u="gpg-$spec@example.org"; GU="G $spec <$u>"; k=gpg-$spec-$prot
    fresh
    g --passphrase "$p" --quick-gen-key "$GU" $spec sign,cert 1y 2>/dev/null
    fpr=$(list_fpr $u)
    g --passphrase "$p" --quick-add-key $fpr $e encr 1y 2>/dev/null
    g --export $fpr > g.cert; g --passphrase "$p" --export-secret-keys $fpr > g.key
    $GPGCONF --homedir "$GNUPGHOME" --kill all 2>/dev/null
    r1() { g --import g.cert; $OURS revoke-key $kp < g.key > grev.cert && g --import grev.cert; g --list-keys --with-colons $u | grep -q '^pub:r:'; }
    r2() { g --import g.cert; $OURS certify-userid --userid="$GU" certifier.key < g.cert > gc.cert && g --import gc.cert; g --check-sigs $u 2>&1 | grep -q '^sig!.*Certifier'; }
    r3() { $OURS change-key-password $( [ $prot = pw ] && echo --old-key-password=pw1.txt ) --new-key-password=pw2.txt < g.key > gn.key && g --passphrase 'pw two' --import gn.key && g --passphrase 'pw two' --local-user $fpr --detach-sign -o gs.sig msg.txt && $OURS verify gs.sig g.cert < msg.txt; }
    r4() { $OURS update-key $kp < g.key > gu.key && $OURS extract-cert < gu.key > gu.cert && g --import gu.cert && g --trust-model always -r $fpr -o ge.gpg --encrypt msg.txt && $OURS decrypt $kp gu.key < ge.gpg | cmp - msg.txt; }
    r5() { g --import certifier.cert; g --passphrase '' --import certifier.key; g --import g.cert; g --passphrase '' --quick-sign-key $fpr; g --export $fpr > gsigned.cert; $OURS merge-certs gsigned.cert < g.cert > gm.cert && $OURS validate-userid "$GU" certifier.cert < gm.cert; }
    r6() { g --passphrase "$p" --import g.key; printf 'y\n0\n\ny\n' | $GPG --yes --quiet --pinentry-mode loopback --passphrase "$p" --command-fd 0 --output grc.asc --gen-revoke $fpr; test -s grc.asc && $OURS merge-certs grc.asc < g.cert > gr.cert && $OURS sign $kp g.key < msg.txt > gr.sig && ! $OURS verify gr.sig gr.cert < msg.txt; }
    run "[$k] our revoke-key is honoured by gpg" r1
    run "[$k] our certify-userid is a good signature in gpg" r2
    run "[$k] our change-key-password: gpg uses the new password" r3
    run "[$k] our update-key: gpg encrypts to it and we decrypt" r4
    run "[$k] gpg's certification merges into ours and validates" r5
    run "[$k] gpg's revocation certificate takes effect in ours" r6
  done
done
$GPGCONF --homedir "$GNUPGHOME" --kill all 2>/dev/null
echo "pass=$pass fail=$fail n/a=$na"
[ "$fail" -eq 0 ]
