#!/usr/bin/env python3
"""Maps the bytes of a keybox blob to the fields GnuPG's kbxutil prints for them, by black-box mutation.

For every byte of the blob's fixed part (everything before the OpenPGP or X.509 data, and the tail between the data and the
checksum) the byte is changed, kbxutil is run on the changed file, and the lines of its output that differ from the unchanged
file's output are recorded. A byte that changes exactly one printed field belongs to that field; the offsets of a multi-byte
field are the run of bytes that change the same line. kbxutil is only executed, never read.

  tools/oracles/kbx-probe.py <kbxutil> <pubring.kbx> <blob-index> [first-byte last-byte]
"""
import subprocess, sys, tempfile, os, struct

def run(kbxutil, path):
    p = subprocess.run([kbxutil, path], capture_output=True, text=True, errors="replace")
    return [l for l in p.stdout.splitlines() if not l.startswith("Checksum")], p.returncode

def blobs(data):
    off = 0
    while off + 4 <= len(data):
        n = struct.unpack(">I", data[off:off + 4])[0]
        yield off, n
        off += n

def main():
    kbxutil, path, index = sys.argv[1], sys.argv[2], int(sys.argv[3])
    data = bytearray(open(path, "rb").read())
    start, length = list(blobs(data))[index]
    data_off, data_len = struct.unpack(">II", data[start + 8:start + 16]) if data[start + 4] != 1 else (length, 0)
    lo = int(sys.argv[4]) if len(sys.argv) > 4 else 4
    hi = int(sys.argv[5]) if len(sys.argv) > 5 else length - 20
    base, _ = run(kbxutil, path)
    tmp = tempfile.mktemp(suffix=".kbx")
    prev = None
    for i in range(lo, hi):
        if data_off <= i < data_off + data_len:
            continue
        m = bytearray(data)
        m[start + i] ^= 0x55
        open(tmp, "wb").write(m)
        out, rc = run(kbxutil, tmp)
        changed = [l for l in out if l not in base]
        gone = [l for l in base if l not in out]
        desc = "; ".join(changed[:3]) if changed else ("(no printed change)" if rc == 0 else "(fails)")
        if len(out) != len(base):
            desc += f" [{len(out) - len(base):+d} lines]"
        print(f"{i:4d} (0x{i:03x}) {data[start + i]:02x}->{m[start + i]:02x}  {desc}")
    os.unlink(tmp)

main()
