#!/usr/bin/env python3
"""Builds the data file the browser suite embeds: the committed fixtures plus, when the vector suites are present, a sample of
Wycheproof signature vectors and x509-limbo testcases.

    tools/gen-browser-data.py <output.json> [--vectors DIR] [--limbo FILE] [--per-file N] [--per-category N]

DIR is the folder holding wycheproof/testvectors_v1 (the layout tools/fetch-wycheproof.sh leaves). The sample is deterministic:
evenly spaced tests of each file, and the first few testcases of each limbo category in file order. Without --vectors only the
fixtures go in, which is what the hosted CI run uses.
"""
import argparse
import base64
import glob
import json
import os

HERE = os.path.dirname(os.path.abspath(__file__))
FIXTURES = os.path.join(HERE, "..", "testdata", "browser")
HASHES = {"SHA-256": "SHA256", "SHA-384": "SHA384", "SHA-512": "SHA512"}


def spread(items, n):
    if len(items) <= n:
        return list(items)
    step = len(items) / n
    return [items[int(i * step)] for i in range(n)]


def wycheproof(vectors, per_file):
    base = os.path.join(vectors, "wycheproof", "testvectors_v1")
    wanted = []
    for pattern in ("ecdsa_secp256r1_sha256*", "ecdsa_secp384r1_sha384*", "ecdsa_secp521r1_sha512*", "ecdsa_secp256r1_sha512*",
                    "ecdsa_brainpoolP256r1_sha256*", "ecdsa_brainpoolP512r1_sha512*", "rsa_signature_2048_sha256*",
                    "rsa_signature_3072_sha256*", "rsa_signature_4096_sha512_test*", "rsa_pss_2048_sha256_mgf1_32_test*",
                    "rsa_pss_3072_sha256_mgf1_32_test*", "rsa_pss_4096_sha512_mgf1_64_test*", "ed25519_test*", "ed448_test*"):
        wanted += sorted(glob.glob(os.path.join(base, pattern + ".json")))
    out = []
    for path in wanted:
        name = os.path.basename(path)
        if "params" in name or "webcrypto" in name:
            continue
        doc = json.load(open(path))
        alg = doc["algorithm"]
        for gi, g in enumerate(doc["testGroups"][:4]):
            tests = g["tests"]
            if alg == "EDDSA":
                key = g["publicKey"]["pk"]
                kind = "ed25519" if g["publicKey"]["curve"] == "edwards25519" else "ed448"
                entry = {"file": name, "kind": kind, "key": key}
            elif alg == "ECDSA":
                kind = "ecdsa-p1363" if "p1363" in name else "ecdsa-der"
                entry = {"file": name, "kind": kind, "hash": HASHES.get(g["sha"]), "spki": g["publicKeyDer"],
                         "curve": g["publicKey"]["curve"]}
            elif alg == "RSASSA-PKCS1-v1_5":
                entry = {"file": name, "kind": "rsa-pkcs1", "hash": HASHES.get(g["sha"]), "spki": g["publicKeyDer"],
                         "n": g["publicKey"]["modulus"], "e": g["publicKey"]["publicExponent"]}
            elif alg == "RSASSA-PSS":
                entry = {"file": name, "kind": "rsa-pss", "hash": HASHES.get(g["sha"]), "mgfHash": HASHES.get(g["mgfSha"]),
                         "sLen": g["sLen"], "n": g["publicKey"]["modulus"], "e": g["publicKey"]["publicExponent"],
                         "spki": g["publicKeyDer"]}
            else:
                continue
            if entry.get("hash", "x") is None:
                continue
            entry["group"] = gi
            entry["tests"] = [{"id": t["tcId"], "msg": t["msg"], "sig": t["sig"], "result": t["result"]}
                              for t in spread(tests, per_file)]
            out.append(entry)
    return out


def limbo(path, per_category):
    cases = json.load(open(path))["testcases"]
    seen = {}
    picked = []
    for tc in cases:
        parts = tc["id"].split("::")
        category = "::".join(parts[:2])
        seen[category] = seen.get(category, 0) + 1
        if seen[category] <= per_category:
            picked.append(tc)
    keep = ("id", "validation_kind", "trusted_certs", "untrusted_intermediates", "peer_certificate", "validation_time",
            "key_usage", "extended_key_usage", "expected_result", "expected_peer_name", "max_chain_depth", "crls")
    return [{k: tc[k] for k in keep if k in tc} for tc in picked]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("output")
    ap.add_argument("--vectors")
    ap.add_argument("--limbo")
    ap.add_argument("--per-file", type=int, default=40)
    ap.add_argument("--per-category", type=int, default=4)
    a = ap.parse_args()
    data = {"version": 1, "fixtures": {}, "wycheproof": [], "limbo": []}
    for path in sorted(glob.glob(os.path.join(FIXTURES, "*"))):
        if os.path.basename(path) != "README.md":
            data["fixtures"][os.path.basename(path)] = base64.b64encode(open(path, "rb").read()).decode()
    if a.vectors:
        data["wycheproof"] = wycheproof(a.vectors, a.per_file)
    if a.limbo:
        data["limbo"] = limbo(a.limbo, a.per_category)
    with open(a.output, "w") as f:
        json.dump(data, f, separators=(",", ":"))
    print(f"fixtures {len(data['fixtures'])}, wycheproof groups {len(data['wycheproof'])} "
          f"({sum(len(g['tests']) for g in data['wycheproof'])} tests), limbo {len(data['limbo'])}, "
          f"{os.path.getsize(a.output)} bytes")


main()
