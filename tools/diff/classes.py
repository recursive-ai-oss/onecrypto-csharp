#!/usr/bin/env python3
"""Groups the disagreements between ours and each oracle into classes.

Usage: classes.py ours.tsv openssl.tsv go.tsv [expected-from-cases.jsonl]
Each tsv row is: id, verdict, message. Prints, per class (oracle, direction, reason with numbers
masked), the count, the corpus-expected verdicts and a few case ids. The reason is our own
message when the oracle accepts and ours rejects, and the oracle's message otherwise.
"""
import collections
import json
import re
import sys


def mask(s):
    return re.sub(r"[0-9]+", "N", s)


def load(p):
    d = {}
    for l in open(p):
        f = l.rstrip("\n").split("\t")
        d[f[0]] = (f[1], f[2] if len(f) > 2 else "")
    return d


ours, ossl, go = load(sys.argv[1]), load(sys.argv[2]), load(sys.argv[3])
exp = {}
if len(sys.argv) > 4:
    for l in open(sys.argv[4]):
        c = json.loads(l)
        exp[c["id"]] = c["expected"]


def ossl_reason(m):
    r = re.search(r"lookup: ([^\n]*?) error /", m) or re.search(r"lookup: (.*)$", m)
    return r.group(1) if r else m[-80:]


classes = collections.defaultdict(list)
for i, (v, m) in ours.items():
    for name, o in (("openssl", ossl), ("go", go)):
        ov, om = o.get(i, ("?", ""))
        if ov == v:
            continue
        if ov == "ACCEPT":
            k = (name + " accepts, ours rejects", mask(m)[:100])
        else:
            k = (name + " rejects, ours accepts", mask(ossl_reason(om) if name == "openssl" else om)[:80])
        classes[k].append(i)
for k, v in sorted(classes.items()):
    print(len(v), k, ",".join(sorted(set(exp.get(i, "?") for i in v))), v[:3])
