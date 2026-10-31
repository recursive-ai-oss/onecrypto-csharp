#!/usr/bin/env python3
"""Writes the chains of the published validation corpora as one JSON line per case, for the differential drivers.

Usage: export-cases.py VECTORS_DIR OUT.jsonl      (VECTORS_DIR holds x509-limbo/limbo.json and bettertls/*.json)
Each line: id, set, trusted[PEM], untrusted[PEM], leaf (PEM), time (ISO 8601 or null for 'now'), name (host or IP or null),
profile ('webpki' for the server-authentication cases, 'rfc5280' otherwise), eku ('serverAuth', 'clientAuth' or null), expected.
"""
import base64
import json
import os
import sys
import textwrap

v, out = sys.argv[1], sys.argv[2]


def pem(der_b64):
    return "-----BEGIN CERTIFICATE-----\n" + "\n".join(textwrap.wrap(der_b64, 64)) + "\n-----END CERTIFICATE-----\n"


n = 0
with open(out, "w") as o:
    limbo = json.load(open(os.path.join(v, "x509-limbo", "limbo.json")))
    for t in limbo["testcases"]:
        if t.get("crls"):
            continue  # revocation data is not part of the OpenSSL/Go comparison
        pn = t.get("expected_peer_name")
        name = pn["value"] if t["validation_kind"] == "SERVER" and pn else None
        webpki = t["id"].startswith(("webpki::", "bettertls::"))
        eku = None
        if t.get("extended_key_usage"):
            eku = t["extended_key_usage"][0]
        elif webpki:
            eku = "serverAuth"
        o.write(json.dumps({
            "id": t["id"], "set": "limbo", "trusted": t["trusted_certs"], "untrusted": t["untrusted_intermediates"],
            "leaf": t["peer_certificate"], "time": t.get("validation_time"), "name": name,
            "profile": "webpki" if webpki else "rfc5280", "eku": eku, "maxDepth": t.get("max_chain_depth"),
            "expected": "ACCEPT" if t["expected_result"] == "SUCCESS" else "REJECT"}) + "\n")
        n += 1
    for suite in ("nameconstraints", "pathbuilding"):
        p = os.path.join(v, "bettertls", suite + ".json")
        if not os.path.exists(p):
            continue
        d = json.load(open(p))
        root = pem(d["trustRoot"])
        for t in d["suites"][suite]["testCases"]:
            certs = [pem(c) for c in t["certificates"]]
            o.write(json.dumps({
                "id": "bettertls-export::%s::%05d" % (suite, t["id"]), "set": "bettertls", "trusted": [root], "untrusted": certs[1:],
                "leaf": certs[0], "time": None, "name": t["hostname"], "profile": "webpki", "eku": "serverAuth", "maxDepth": None,
                "expected": t["expected"]}) + "\n")
            n += 1
print(n, "cases")
