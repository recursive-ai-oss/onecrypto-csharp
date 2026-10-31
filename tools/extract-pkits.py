#!/usr/bin/env python3
"""Reads NIST's PKITS document (as text from `pdftotext -layout PKITS.pdf`) and writes a manifest of the path-validation
tests in sections 4.1 to 4.16: for each test the objects of its certification path and every run (settings and expected result).
The certificates and CRLs themselves come from PKITS_data.zip (tools/fetch-pkits.sh).

Usage: extract-pkits.py PKITS.txt PKITS_data_dir out.json
"""
import json
import os
import re
import sys

text = open(sys.argv[1], encoding="utf-8", errors="replace").read().splitlines()
data = sys.argv[2]
files = {f.lower(): f for d in ("certs", "crls") for f in os.listdir(os.path.join(data, d))}

start = next(i for i, l in enumerate(text) if l.startswith("6 Test Data Descriptions") and "...." not in l)
head = re.compile(r"^\s*(4\.(\d+)\.(\d+))\s+(\S.*)$")
blocks = []
for i, l in enumerate(text[:start]):
    m = head.match(l)
    if m and i > 100:
        blocks.append((i, m.group(1), m.group(4).strip()))
blocks.append((start, None, None))


def fname(obj):
    s = re.sub(r"[^A-Za-z0-9]", "", obj)
    return s


def resolve(name, kind):
    base = fname(name)
    for ext in ("crt", "crl"):
        f = files.get((base + "." + ext).lower())
        if f:
            return f
    return None


def settings_of(s):
    out = {}
    if re.search(r"initial-explicit-policy (indicator )?(is )?set", s) and "not set" not in s.split("initial-explicit-policy")[1][:25]:
        out["explicit"] = True
    if re.search(r"initial-policy-mapping-inhibit (indicator )?(is )?set", s):
        out["inhibitMapping"] = True
    if re.search(r"initial-(any-policy-inhibit|inhibit-any-policy) (indicator )?(is )?set", s):
        out["inhibitAny"] = True
    m = re.search(r"initial-policy-set\s*=\s*\{([^}]*)\}", s)
    if m:
        pols = re.findall(r"NIST-test-policy-(\d)", m.group(1))
        out["policies"] = ["2.16.840.1.101.3.2.1.48." + p for p in pols]
    return out


tests = []
unparsed = []
for (i, tid, title), (j, _, _) in zip(blocks, blocks[1:]):
    if tid is None:
        continue
    body = text[i:j]
    joined = "\n".join(body)
    # certification path objects
    path = []
    k = next((n for n, l in enumerate(body) if "Certification Path" in l), None)
    if k is None:
        unparsed.append((tid, "no path"))
        continue
    cur = None
    items = []
    for l in body[k + 1:]:
        if "•" in l:
            if cur is not None:
                items.append(cur)
            cur = l.split("•", 1)[1].strip()
        elif cur is not None and l.strip() and not re.match(r"^\s*\d+\s*$", l) and not l.strip().startswith(("4.", "Procedure")):
            cur += " " + l.strip()
        elif cur is not None and not l.strip():
            items.append(cur)
            cur = None
    if cur is not None:
        items.append(cur)
    objs = []
    for it in items:
        for part in re.split(r",\s*", it):
            part = part.strip()
            if part:
                objs.append(part)
    certs, crls, bad = [], [], []
    target = None
    for o in objs:
        if o == "Trust Anchor Root Certificate":
            continue
        f = resolve(o, None)
        if f is None:
            bad.append(o)
        elif f.endswith(".crl"):
            crls.append(f)
        else:
            certs.append(f)
    if bad:
        unparsed.append((tid, "unmapped: " + "; ".join(bad)))
    # runs
    runs = []
    numbered = re.findall(r"^\s+(\d+)\.\s+((?:(?!^\s+\d+\.\s).)*?)(?=^\s+\d+\.\s|\n\s*Procedure)", joined, re.S | re.M)
    for _, t in numbered:
        t = " ".join(t.split())
        exp = "invalid" if re.search(r"should not validate|should be rejected|not validate successfully", t) else "valid" if re.search(r"should validate|validate successfully", t) else None
        if exp:
            runs.append({"settings": settings_of(t), "expected": exp, "note": t[:160]})
    if not runs:
        flat = " ".join(joined.split())
        pm = re.search(r"Procedure:(.*?)Expected Result:(.*?)Certification Path", flat)
        proc = pm.group(1) if pm else ""
        exp_t = pm.group(2) if pm else flat
        if "The authorities-constrained" in exp_t[:60] or "authorities-constrained" in exp_t[:80]:
            # Stated as conditions on the inputs. A rejection counts only when no condition on the user's initial-policy-set
            # or explicit-policy setting is attached to it, because the runs here use the default settings unless a numbered list says otherwise.
            exp = "valid"
            for sent in re.split(r"(?<=\.)\s+", exp_t):
                if re.search(r"should not validate|not should validate|should be rejected|not validate successfully", sent) and not re.search(r"initial-policy-set|initial-explicit|user-constrained|initial-inhibit|initial-policy-mapping", sent):
                    exp = "invalid"
        elif re.search(r"should not validate|not should validate|should be rejected|not validate successfully", exp_t):
            exp = "invalid"
        elif re.search(r"should validate|validate successfully", exp_t):
            exp = "valid"
        else:
            exp = None
        if exp:
            runs.append({"settings": settings_of(proc), "expected": exp, "note": exp_t[:160]})
    if not runs:
        unparsed.append((tid, "no run"))
        continue
    tests.append({"id": tid, "title": title, "certs": certs, "crls": crls, "runs": runs})

json.dump({"source": "NIST PKITS v1.0.1 (April 14, 2011), section 4", "tests": tests}, open(sys.argv[3], "w"), indent=1)
print(len(tests), "tests,", sum(len(t["runs"]) for t in tests), "runs")
for u in unparsed:
    print("UNPARSED", *u)
