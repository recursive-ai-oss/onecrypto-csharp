# Extracts the armored sample keys, messages and signatures of RFC 9980 Appendix A.1 to A.4 into testdata/openpgp/rfc9980.
# Usage: python3 tools/extract-rfc9980-vectors.py path/to/rfc9980.txt
import re, os, sys
txt = open('' + (sys.argv[1] if len(sys.argv) > 1 else 'rfc9980.txt') + '').read().split('\n')
# drop page furniture
out = []
for l in txt:
    if re.match(r'^(Wussler|RFC 9980|Kousidis|Strenzke|Roth|Weiler|Ludwig)', l) and ('[Page' in l or 'June' in l or 'Post-Quantum' in l):
        continue
    out.append(l)
text = out
names = {
 '1.1': 'A_1_sec', '1.2': 'A_1_pub', '1.3': 'A_1_msg',
 '2.1': 'A_2_sec', '2.2': 'A_2_pub', '2.3': 'A_2_msg_seipd1', '2.4': 'A_2_msg_seipd2',
 '3.1': 'A_3_sec', '3.2': 'A_3_pub', '3.3': 'A_3_msg', '3.4': 'A_3_sig',
 '4.1': 'A_4_sec', '4.2': 'A_4_pub', '4.3': 'A_4_msg', '4.4': 'A_4_sig',
}
cur = None
dest = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'testdata', 'openpgp', 'rfc9980')
os.makedirs(dest, exist_ok=True)
i = 0
blocks = {}
while i < len(text):
    m = re.match(r'^A\.(\d)\.(\d)\.\s', text[i])
    if m: cur = f'{m.group(1)}.{m.group(2)}'
    if text[i].strip().startswith('-----BEGIN PGP') and cur:
        j = i
        lines = []
        while True:
            lines.append(text[j].strip()); 
            if text[j].strip().startswith('-----END PGP'): break
            j += 1
        # remove empty lines inside the armor body except the header separator
        res = []
        seen_blank = False
        for l in lines:
            if l == '' and seen_blank: continue
            if l == '': seen_blank = True
            res.append(l)
        blocks.setdefault(cur, []).append('\n'.join(res) + '\n')
        i = j
    i += 1
for k, v in blocks.items():
    if k in names:
        for n, b in enumerate(v):
            fn = names[k] + ('' if n == 0 else f'_{n}') + '.asc'
            open(f'{dest}/{fn}', 'w').write(b)
            print(fn, len(b))
