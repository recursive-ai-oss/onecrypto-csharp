# Extracts the examples of the Autocrypt Level 1 specification (https://autocrypt.org/level1.html, CC0) into testdata/openpgp/autocrypt:
# the example Autocrypt header value, the setup message with its setup code, the decrypted secret key, and the encrypted gossip message.
# Usage: python3 tools/extract-autocrypt-vectors.py path/to/level1.html
import html, os, re, sys

src = open(sys.argv[1] if len(sys.argv) > 1 else 'level1.html', encoding='utf8').read()
src = re.sub(r'<(script|style)[^>]*>.*?</\1>', '', src, flags=re.S)
text = html.unescape(re.sub(r'<[^>]+>', '', src))
lines = [l.rstrip() for l in text.split('\n')]
dest = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'testdata', 'openpgp', 'autocrypt')
os.makedirs(dest, exist_ok=True)


def armored(start_idx):
    out = []
    i = start_idx
    while True:
        out.append(lines[i].strip())
        if out[-1].startswith('-----END PGP'):
            return out, i
        i += 1


def write(name, body):
    with open(os.path.join(dest, name), 'w', newline='\n') as f:
        f.write(body)


# The first example header: "Autocrypt: addr=...; keydata=" followed by indented Base64 lines.
for i, l in enumerate(lines):
    if l.startswith('Autocrypt: addr=alice@autocrypt.example'):
        value = [l[len('Autocrypt:'):].strip()]
        j = i + 1
        while lines[j].startswith(' '):
            value.append(lines[j].strip())
            j += 1
        write('alice-header-value.txt', value[0] + '\n' + '\n'.join(' ' + v for v in value[1:]) + '\n')
        break

# Setup code: the three-line number of "Example User Interaction for Setup Message Creation".
code = None
for i, l in enumerate(lines):
    if "You'll need to use this Setup Code" in l:
        digits = []
        for k in range(i + 1, i + 6):
            m = re.match(r'^\s*(\d{4}-\d{4}-\d{4}-?)\s*$', lines[k])
            if m:
                digits.append(m.group(1))
        code = ''.join(digits)
        break
assert code and len(code) == 44, code
write('setup-code.txt', code + '\n')

# The setup message block (first PGP MESSAGE after "Example Setup Message") and the decrypted key block.
msg_start = next(i for i, l in enumerate(lines) if l.strip().endswith('-----BEGIN PGP MESSAGE-----') and lines[i + 1].startswith('Passphrase-Format'))
block, end = armored(msg_start)
block[0] = '-----BEGIN PGP MESSAGE-----'
# Armor headers (Passphrase-Format, Passphrase-Begin) are followed directly by the Base64 here; a blank line must separate them.
hdr = [b for b in block[1:] if re.match(r'^[A-Za-z-]+: ', b)]
rest = [b for b in block[1:] if b and b not in hdr]
write('setup-message.asc', '\n'.join([block[0]] + hdr + [''] + rest) + '\n')
key_start = next(i for i in range(end, len(lines)) if lines[i].strip() == '-----BEGIN PGP PRIVATE KEY BLOCK-----')
kb, _ = armored(key_start)
hdr = [b for b in kb[1:] if re.match(r'^[A-Za-z-]+: ', b)]
rest = [b for b in kb[1:] if b and b not in hdr]
write('setup-key.asc', '\n'.join([kb[0]] + hdr + [''] + rest) + '\n')

# The gossip example: Alice's PGP/MIME message to Bob and Carol.
g = next(i for i, l in enumerate(lines) if l.startswith('Example Autocrypt Gossip headers'))
m_start = next(i for i in range(g, len(lines)) if lines[i].strip() == '-----BEGIN PGP MESSAGE-----')
mb, _ = armored(m_start)
body = [b for b in mb[1:]]
write('gossip-message.asc', '\n'.join([mb[0], ''] + [b for b in body if b]) + '\n')
print('ok', code)
