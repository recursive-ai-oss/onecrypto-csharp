#!/usr/bin/env python3
"""Prints, for each scenario, the verdict lines the reference tools gave (for reading expectations quickly)."""
import json, glob, os, re, sys
root = sys.argv[1]
pat = sys.argv[2] if len(sys.argv) > 2 else ""
for d in sorted(glob.glob(os.path.join(root, "*"))):
    if pat and not re.search(pat, d):
        continue
    meta = json.load(open(os.path.join(d, "scenario.json")))
    for p in sorted(glob.glob(os.path.join(d, "expected.*.json"))):
        e = json.load(open(p))
        print("##", meta["name"], e["oracle"])
        for r in e["results"]:
            q = r["query"]
            if "stdout" in r:
                lines = [l.strip() for l in r["stdout"].splitlines() if re.search(r"\[ .* \]|Path #|Error|No bindings|not authenticated", l)]
                err = [l.strip() for l in r["stderr"].splitlines() if l.strip()][:2]
                print("  ", q["targetName"], q["userId"], "t=%d" % q["at"], "exit", r["exit"], "|", " ; ".join(lines)[:300], "|", " ".join(err)[:200])
            else:
                print("  ", q["targetName"], q["userId"], "t=%d" % q["at"], "pub", r["pub"], [(u["userId"][:12], u["validity"]) for u in r["uids"]])
