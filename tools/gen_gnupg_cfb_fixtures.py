#!/usr/bin/env python3
"""Writes OpenPGP symmetric-encryption fixtures produced by an installed GnuPG, used as a black box.

usage: gen_gnupg_cfb_fixtures.py OUTPUT_FILE   (run with GNUPGHOME pointing at a throwaway directory)

The passphrase goes through the simple S2K with SHA-256 (RFC 9580 section 3.7.1.1), so the session key is the first key-size
bytes of SHA-256(passphrase) and the fixture can be decrypted without any S2K code. The packet framing (RFC 9580 section 4.2) is
stripped here: each line holds the cipher, the key, whether the data is the older unprotected packet (feedback register
resynchronised after the prefix) and the CFB data. The test decrypts the data and checks the prefix, the message and the trailer.

line: cipher-id key-hex resync(0|1) ciphertext-hex message-hex
"""
import hashlib
import os
import subprocess
import sys
import tempfile

out = sys.argv[1]
PASSPHRASE = "test-passphrase"
MESSAGE = b"The quick brown fox jumps over the lazy dog, twice over.\n"
# gpg name, OpenPGP cipher id (RFC 9580 section 9.3), key bytes
CIPHERS = [("IDEA", 1, 16), ("CAST5", 3, 16), ("BLOWFISH", 4, 16), ("TWOFISH", 10, 32), ("CAMELLIA128", 11, 16), ("CAMELLIA192", 12, 24), ("CAMELLIA256", 13, 32)]


def packets(data):
    i = 0
    while i < len(data):
        b = data[i]
        assert b & 0x80
        if b & 0x40:
            tag = b & 0x3F
            n = data[i + 1]
            if n < 192:
                i += 2
            elif n < 224:
                n = ((n - 192) << 8) + data[i + 2] + 192
                i += 3
            else:
                assert n == 255
                n = int.from_bytes(data[i + 2:i + 6], "big")
                i += 6
        else:
            tag = (b >> 2) & 0x0F
            lt = b & 3
            size = {0: 1, 1: 2, 2: 4}[lt]
            n = int.from_bytes(data[i + 1:i + 1 + size], "big")
            i += 1 + size
        yield tag, data[i:i + n]
        i += n


lines = []
with tempfile.TemporaryDirectory() as tmp:
    plain = os.path.join(tmp, "msg")
    open(plain, "wb").write(MESSAGE)
    for name, cid, klen in CIPHERS:
        for protected in (True, False):
            target = os.path.join(tmp, "out.gpg")
            if os.path.exists(target):
                os.remove(target)
            args = ["gpg", "--batch", "--yes", "--pinentry-mode", "loopback", "--passphrase", PASSPHRASE, "--symmetric", "--cipher-algo", name,
                    "--s2k-mode", "0", "--s2k-digest-algo", "SHA256", "--compress-algo", "none", "--allow-old-cipher-algos", "-o", target, plain]
            if not protected:
                args.insert(2, "--rfc2440")
            p = subprocess.run(args, capture_output=True, stdin=subprocess.DEVNULL, timeout=20)
            if p.returncode != 0:
                print("skipped", name, protected, p.stderr.decode().strip(), file=sys.stderr)
                continue
            data = open(target, "rb").read()
            key = hashlib.sha256(PASSPHRASE.encode()).digest()[:klen]
            for tag, body in packets(data):
                if tag == 18:
                    assert body[0] == 1
                    lines.append(" ".join([str(cid), key.hex(), "0", body[1:].hex(), MESSAGE.hex()]))
                elif tag == 9:
                    lines.append(" ".join([str(cid), key.hex(), "1", body.hex(), MESSAGE.hex()]))

ver = subprocess.run(["gpg", "--version"], capture_output=True).stdout.decode().splitlines()[0]
with open(out, "w", newline="\n") as f:
    f.write("# OpenPGP symmetric-key encrypted data written by %s as the oracle (tools/gen_gnupg_cfb_fixtures.py).\n" % ver)
    f.write("# cipher-id key resync ciphertext message (hex). The key is the first bytes of SHA-256 of the passphrase 'test-passphrase'.\n")
    f.write("\n".join(lines) + "\n")
