#!/usr/bin/env python3
"""Runs `openssl verify` on every case of a cases.jsonl and writes `id<TAB>ACCEPT|REJECT<TAB>detail` lines.
OPENSSL names the binary (default: openssl). The binary is only executed.

Usage: openssl_driver.py cases.jsonl out.tsv
"""
import concurrent.futures
import datetime
import ipaddress
import json
import os
import subprocess
import sys
import tempfile

openssl = os.environ.get("OPENSSL", "openssl")


def run(case):
    with tempfile.TemporaryDirectory() as d:
        def w(name, pems):
            p = os.path.join(d, name)
            with open(p, "w") as f:
                f.write("".join(pems))
            return p

        args = [openssl, "verify", "-CAfile", w("ca.pem", case["trusted"]), "-no-CApath", "-no-CAstore"]
        if case["untrusted"]:
            args += ["-untrusted", w("inter.pem", case["untrusted"])]
        if case["time"]:
            t = datetime.datetime.fromisoformat(case["time"]).astimezone(datetime.timezone.utc)
            args += ["-attime", str(int(t.timestamp()))]
        else:
            args += []
        if case["profile"] == "webpki" and case["eku"] == "serverAuth":
            args += ["-purpose", "sslserver"]
        elif case["eku"] == "clientAuth":
            args += ["-purpose", "sslclient"]
        if case["name"]:
            try:
                ipaddress.ip_address(case["name"])
                args += ["-verify_ip", case["name"]]
            except ValueError:
                args += ["-verify_hostname", case["name"]]
        if case["maxDepth"] is not None:
            args += ["-verify_depth", str(case["maxDepth"] + 1)]
        args.append(w("leaf.pem", [case["leaf"]]))
        try:
            r = subprocess.run(args, capture_output=True, text=True, timeout=30)
        except subprocess.TimeoutExpired:
            return case["id"], "REJECT", "timeout"
        ok = r.returncode == 0 and ": OK" in r.stdout
        detail = " ".join((r.stdout + r.stderr).replace(d, "").split())[-160:]
        return case["id"], "ACCEPT" if ok else "REJECT", detail


cases = [json.loads(l) for l in open(sys.argv[1])]
with concurrent.futures.ThreadPoolExecutor(max_workers=int(os.environ.get("JOBS", "8"))) as ex, open(sys.argv[2], "w") as out:
    for id_, verdict, detail in ex.map(run, cases):
        out.write(f"{id_}\t{verdict}\t{detail}\n")
