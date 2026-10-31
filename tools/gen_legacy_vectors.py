#!/usr/bin/env python3
"""Writes known-answer vectors for Camellia, CAST5, IDEA and Blowfish produced by an OpenSSL binary used as a black box.

usage: gen_legacy_vectors.py PATH_TO_OPENSSL OUTPUT_FILE

The legacy ciphers need the legacy provider. Keys, IVs and plaintexts come from a fixed seed, so the file is reproducible.
Each line is: cipher mode key-hex iv-hex plaintext-hex ciphertext-hex. Modes: ecb (no padding), cbc (PKCS #7 padding), cfb (full block).
"""
import os
import random
import subprocess
import sys

openssl, out = sys.argv[1:3]
rng = random.Random(20261031)

# (name, OpenSSL algorithm prefix, key bytes, block bytes)
CIPHERS = [
    ("camellia128", "camellia-128", 16, 16),
    ("camellia192", "camellia-192", 24, 16),
    ("camellia256", "camellia-256", 32, 16),
    ("cast5", "cast5", 16, 8),
    ("idea", "idea", 16, 8),
    ("blowfish", "bf", 16, 8),
]

libdir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(openssl))), "lib")
env = dict(os.environ)
env["LD_LIBRARY_PATH"] = libdir + ":" + env.get("LD_LIBRARY_PATH", "")
env["DYLD_LIBRARY_PATH"] = libdir + ":" + env.get("DYLD_LIBRARY_PATH", "")
modules = os.path.join(libdir, "ossl-modules")
if os.path.isdir(modules):
    env["OPENSSL_MODULES"] = modules


def run(args, data):
    p = subprocess.run([openssl, "enc", "-provider", "legacy", "-provider", "default", *args], input=data, capture_output=True, env=env)
    if p.returncode != 0:
        raise SystemExit("openssl failed: " + p.stderr.decode())
    return p.stdout


lines = []
for name, prefix, klen, bs in CIPHERS:
    for mode, lengths in (("ecb", [bs, 2 * bs, 7 * bs]), ("cbc", [0, 1, bs - 1, bs, bs + 1, 5 * bs + 3]), ("cfb", [0, 1, bs - 1, bs, bs + 1, 5 * bs + 3, 100])):
        for length in lengths:
            key = rng.randbytes(klen)
            iv = rng.randbytes(bs)
            data = rng.randbytes(length)
            args = ["-" + prefix + "-" + mode, "-K", key.hex()]
            if mode != "ecb":
                args += ["-iv", iv.hex()]
            if mode == "ecb":
                args += ["-nopad"]
            ct = run(args, data)
            lines.append(" ".join([name, mode, key.hex(), iv.hex() if mode != "ecb" else "-", data.hex() or "-", ct.hex() or "-"]))

with open(out, "w", newline="\n") as f:
    f.write("# Known-answer vectors written by tools/gen_legacy_vectors.py with OpenSSL %s as the oracle.\n" % subprocess.run([openssl, "version"], capture_output=True, env=env).stdout.decode().strip())
    f.write("# cipher mode key iv plaintext ciphertext (hex; - is empty). ecb: no padding. cbc: PKCS #7. cfb: full-block segments.\n")
    f.write("\n".join(lines) + "\n")
