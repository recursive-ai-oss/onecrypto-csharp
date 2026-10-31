# Loading key and certificate files: `Crypto.Load`

Behaviour of `RecursiveAI.OneCrypto.Crypto.Load`, `LoadAsync` and `TryLoad`. The loader only decides which parser to call and gathers what the parsers return; every format is read by the type that owns it (`Certificate`, `PrivateKeyInfo`, `Pkcs12File`, `SshPrivateKey` and so on), so a rule written elsewhere (`pkcs.md`, `x509.md`, `asn1.md`) applies unchanged.

## Result

`LoadedItems`, in file order, with typed lists: `Certificates`, `Crls`, `CertificateRequests`, `OcspResponses`, `PublicKeys` (`PublicKeyInfo`), `PrivateKeys` (`LoadedPrivateKey`), `SshPublicKeys`, `SshCertificates`; `Format` names the container that was detected and `Count` is the total. Dispose it to zero the private keys.

A `LoadedPrivateKey` carries `Signing` (`ISigningKey`), `Decryption` (`IDecryptionKey`) and `Agreement` (`IAgreementKey`) as the algorithm allows, the `PublicKey`, the pinned PKCS#8 `Info`, and `Comment`, `FriendlyName`, `Certificate` (PKCS#12 `localKeyId` match) and `SshPublicKey` where the container has them.

| Algorithm | `Signing` | `Decryption` | `Agreement` |
|---|---|---|---|
| RSA (also RSASSA-PSS / RSAES-OAEP keys) | yes | yes (one `IRsaKey`) | |
| EC P-256/384/521 | ECDSA | | ECDH |
| Ed25519, Ed448, ML-DSA | yes | | |
| X25519, X448 | | | yes |
| ML-KEM | | yes | |
| DSA and others | none; `Info` still holds the key | | |

Platform-dependent algorithms (ML-DSA, ML-KEM, Brainpool, ...) that the platform lacks give `CryptoLoadError.Unsupported`.

## The decision table

Sniffing reads the first byte, the PEM labels and the outline of the ASN.1 structure. It picks exactly one parser per item and calls it. It never calls several and keeps the one that did not throw.

1. Empty or white space only: `Empty`. A UTF-8 byte order mark is skipped.
2. First byte `0x30` (no leading white space): binary ASN.1, DER or BER. Trailing white space and zero bytes are allowed; other trailing data is `Malformed` (one file holds one element). Text that happens to start with the character `0` is therefore read as binary; real files do not.
3. Starts with `openssh-key-v1\0`: the binary OpenSSH private key form.
4. First four bytes a small big-endian length, then `ssh-`, `ecdsa-sha2-` or `sk-`: an OpenSSH public key or certificate wire blob (RFC 4253 §6.6).
5. Otherwise text. If it holds a `-----BEGIN ` line: PEM (RFC 7468, lax mode: any line length and whitespace, `Proc-Type`/`DEK-Info` headers), every block read in order, text outside blocks ignored. Else if it holds `---- BEGIN SSH2 PUBLIC KEY ----`: RFC 4716. Else each non-blank, non-`#` line is an `authorized_keys` line (options allowed), a certificate when it contains `-cert-v01@openssh.com`. A first line that is not a key is `Unrecognized`; a later bad line is `Malformed` and names its line.

### PEM labels

| Label | Read as |
|---|---|
| `CERTIFICATE`, `X509 CERTIFICATE` | `Certificate` |
| `TRUSTED CERTIFICATE` | `Certificate` (the first element; OpenSSL's trust settings after it are not read) |
| `X509 CRL` | `CertificateRevocationList` |
| `CERTIFICATE REQUEST`, `NEW CERTIFICATE REQUEST` | `CertificateSigningRequest` |
| `OCSP RESPONSE` | `OcspResponse` |
| `PUBLIC KEY` | `PublicKeyInfo` |
| `RSA PUBLIC KEY` | PKCS#1 `RSAPublicKey` (RFC 8017 A.1.1), wrapped as `SubjectPublicKeyInfo` (RFC 3279 §2.3.1) |
| `PRIVATE KEY`, `ENCRYPTED PRIVATE KEY` | PKCS#8 (RFC 5958), PBES2 and the PKCS#12 PBEs |
| `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `DSA PRIVATE KEY` | PKCS#1 / SEC 1 (RFC 5915) / DSA, with the legacy `DEK-Info` encryption |
| `OPENSSH PRIVATE KEY` | `SshPrivateKey` |
| `PKCS7`, `CMS` | SignedData certificate bag |
| `EC PARAMETERS`, `DH PARAMETERS`, `DSA PARAMETERS`, `X9.42 DH PARAMETERS`, `PARAMETERS` | skipped (OpenSSL writes them beside keys) |
| `ATTRIBUTE CERTIFICATE` | `Unsupported`; use `AttributeCertificate.Parse` |
| `PGP ...` and any other label | `Unrecognized`; OpenPGP armor is read by the OpenPGP package, not here |

### DER outline rules

With X the outer SEQUENCE and c0, c1, ... its children, in order:

1. c0 is a SEQUENCE and X has exactly three children, the last a BIT STRING, c1 a SEQUENCE: a signed structure, told by the first child t0 of c0 (RFC 5280 §4.1.1, §5.1.1):
   * t0 is `[0]`: `Certificate`.
   * t0 is a SEQUENCE: a v1 `CertificateRevocationList`.
   * t0 is an INTEGER and the next element is a SEQUENCE whose first child is an OID: the element after the issuer name is a SEQUENCE (validity) for a v1 `Certificate`, a time for a v2 `CertificateRevocationList`.
   * t0 is an INTEGER and the next element is a SEQUENCE whose first child is a SET or that is empty: `CertificateSigningRequest` (RFC 2986 §4.1).
   * t0 is an INTEGER and the next element is a SEQUENCE with a context-tagged first child: an attribute certificate (`Unsupported`).
2. c0 is an ENUMERATED and X has at most two children: `OcspResponse` (RFC 6960 §4.2.1).
3. c0 is an INTEGER:
   * c1 is a SEQUENCE whose second child is `[0]`: PKCS#12 `Pfx` (RFC 7292 §4). A `PrivateKeyInfo` algorithm identifier never has a context-tagged second child.
   * c1 a SEQUENCE and c2 an OCTET STRING: PKCS#8 `PrivateKeyInfo`.
   * c1 an OCTET STRING: SEC 1 `ECPrivateKey`.
   * c1 an INTEGER: two children are a PKCS#1 `RSAPublicKey`, nine or more an `RSAPrivateKey`, six a DSA private key.
4. c0 is a SEQUENCE and X has two children: a BIT STRING second is a `SubjectPublicKeyInfo`, an OCTET STRING second is an `EncryptedPrivateKeyInfo`.
5. c0 is an OID and c1 is `[0]`: a CMS `ContentInfo`. Only SignedData with no signers and no content (a `.p7b`/`.p7c` certificate bag) is loaded; any other content type, or a SignedData that carries signatures or content, is `Unsupported` and points at the CMS API.
6. Anything else is `Unrecognized`, with the outline in the reason.

BER with indefinite lengths is read in the outline and by the parsers (PKCS#12 and PKCS#7 files from some tools use it).

## Passwords

The callback receives a short description of the encrypted item (for example `PEM block 2 (ENCRYPTED PRIVATE KEY)`, `OpenSSH private key ssh-ed25519 SHA256:...`) and returns the password, or null.

* It is called at most once per encrypted item.
* A password that opened an earlier item is tried on later ones first, so one passphrase for a whole bundle asks once.
* A PKCS#12 file for which no password is supplied (no callback, or the callback returns null) is tried with the empty password, both of its encodings (`pkcs.md`). A supplied password is never replaced by the empty one.
* No callback, or null returned: `PasswordRequired`. A password that does not open the item: `WrongPasswordOrCorrupt` (a wrong password and damage cannot be told apart).
* Any failure fails the whole load; nothing from the file is returned, and keys already made are disposed.
* Passwords are managed strings; the library cannot erase them.

A PKCS#12 file without a MAC is refused (`Unsupported`), as in `pkcs.md`.

## Limits

On by default and taken from `PkcsLimits.Default`: input 64 MiB, ASN.1 depth 24, PBKDF2/PKCS#12 iterations 5,000,000, scrypt and bcrypt costs as in `pkcs.md`, 4096 PKCS#12 bags. An input over a limit is `LimitExceeded` before the expensive work. The loader has no option to change them.

## Errors

Bad input raises only `CryptoLoadException` (`Error`: `Empty`, `Unrecognized`, `Malformed`, `Unsupported`, `PasswordRequired`, `WrongPasswordOrCorrupt`, `LimitExceeded`), whose `Considered` lists the formats looked at, in table order, each with the reason it did not apply or what was wrong. `TryLoad` returns it. I/O errors reading a stream or path propagate. A mutation test over the generated corpus and a fuzz target (`load`) check that nothing else escapes.

## Not loaded here

OpenPGP keys and messages (armor labels `PGP ...` are reported as unrecognised, with that reason; the OpenPGP package will have its own loader), age, minisign and Sigstore files, attribute certificates, CMS content other than certificate bags, network sources. There is no extension registry: the table is static code, which keeps the loader trim- and AOT-safe.

## How it is checked

`CryptoLoadTests` generates the corpus when it runs: OpenSSL (keys of every type in PKCS#8 PEM/DER, encrypted PKCS#8 with PBKDF2 and scrypt, traditional and `DEK-Info` forms, SubjectPublicKeyInfo and PKCS#1 public keys, certificates with and without surrounding text, requests, a CRL and an OCSP response, `.p7b`, PKCS#12 in default, 3DES/SHA-1 and empty-password forms), `ssh-keygen` (RSA, ECDSA and Ed25519 keys with and without passphrase, public keys, RFC 4716, certificates, `authorized_keys`) and the platform's exporters. Each file must load as the right type with the right algorithm and public key, and every private key must sign and verify, decrypt or agree. A mutation test then loads damaged copies of every file and accepts only `CryptoLoadException`.
