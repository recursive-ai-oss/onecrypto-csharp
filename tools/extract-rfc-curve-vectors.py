#!/usr/bin/env python3
"""Extracts the EdDSA vectors of RFC 8032 section 7 from the plain-text RFC into JSON the tests read.   usage: extract-rfc-curve-vectors.py rfc8032.txt outdir"""
import json, re, sys

def body(path):
    lines = []
    for l in open(path, encoding='utf-8').read().split('\n'):
        if l.startswith('\f') or re.match(r'^(Josefsson|Langley|RFC )', l):
            continue
        lines.append(l)
    return lines

def eddsa(path):
    lines = body(path)
    start = next(i for i, l in enumerate(lines) if l.startswith('7.  Test Vectors'))
    end = next(i for i, l in enumerate(lines) if l.startswith('8.  '))
    out, cur, field = [], None, None
    for l in lines[start:end]:
        s = l.strip()
        if s.startswith('-----'):
            cur = {'name': s[5:], 'hex': {}}
            out.append(cur); field = None; continue
        if cur is None: continue
        m = re.match(r'^(ALGORITHM|SECRET KEY|PUBLIC KEY|MESSAGE|CONTEXT|SIGNATURE)\b(.*):$', s)
        if m:
            field = m.group(1); cur['hex'].setdefault(field, ''); continue
        if field == 'ALGORITHM' and s:
            cur['algorithm'] = s; field = None; continue
        if field and re.fullmatch(r'[0-9a-f]+', s):
            cur['hex'][field] += s
        elif s.startswith('7.'):
            cur = None
    res = []
    for v in out:
        h = v['hex']
        if 'SIGNATURE' not in h: continue
        res.append({'name': v['name'], 'algorithm': v.get('algorithm'), 'secret': h.get('SECRET KEY', ''), 'public': h.get('PUBLIC KEY', ''),
                    'message': h.get('MESSAGE', ''), 'context': h.get('CONTEXT'), 'signature': h['SIGNATURE']})
    return res

if __name__ == '__main__':
    r8032, out = sys.argv[1:3]
    json.dump(eddsa(r8032), open(out + '/rfc8032.json', 'w'), indent=1)
    print('rfc8032 vectors:', len(eddsa(r8032)))
