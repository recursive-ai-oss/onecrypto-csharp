# Conformance

What is checked, against what, and where the library deviates. Gaps are listed, not hidden. The numbers come from runs of the test suite and its opt-in vector and oracle tests (see each area's document). This table is updated at each release.

Oracles run black-box at pinned versions: OpenSSL 3.5.9, Go 1.26.8, GnuPG 2.4.8, OpenSSH 9.6 (and 10.2), .NET 10.0.

| Area | Vectors and suites | Interoperability | Documented deviations and gaps | Details |
|---|---|---|---|---|
| ASN.1 BER/CER/DER, PEM | `AsnReader` differential: x509-limbo 40,194, Wycheproof 62,682, 2M generated valid inputs, 0 differences; 2M mutated inputs, 27 differences, all documented | n/a | tag 0, BER unused bits kept, GeneralizedTime minute/hour fractions refused, OID arcs up to 128 bits, UniversalString | [asn1.md](asn1.md) |
| Ed25519, Ed448, X25519, X448 | RFC 8032 21/21, RFC 7748 incl. 1,000,000 iterations, Wycheproof ed25519 210, ed448 87, x25519 518, x448 510, C2SP CCTV ed25519 914/914 | OpenSSL 3.5.9, both directions, x64 and arm64 | verification semantics: [curves.md](curves.md) | [curves.md](curves.md) |
| OCB3, EAX, AES-KW | RFC 7253, EAX paper vectors, RFC 3394, Wycheproof aes_eax / aes_wrap / aes_kwp files | OpenSSL 3.5.9 | AES-KWP comes from the platform | [aes-modes.md](aes-modes.md) |
| Argon2, scrypt, bcrypt-pbkdf | RFC 9106 3/3, RFC 7693 1/1, RFC 7914 §12 4/4 and §13, RFC 9580 A.12 3/3 | `openssl kdf` 20/20, `ssh-keygen` bcrypt keys 5/5 | Argon2d, scrypt and bcrypt-pbkdf have data-dependent memory access by design; no constant-time claim for them | [kdf.md](kdf.md) |
| Camellia; CAST5, IDEA, Blowfish, Twofish (decrypt only) | RFC 3713 3/3, RFC 2144 B.1 3/3 and B.2, published IDEA/Blowfish/Twofish known answers, Wycheproof camellia_cbc 216/216 | OpenSSL 3.5.9 both directions; GnuPG 2.4.8 OpenPGP-CFB fixtures 14/14 | legacy ciphers are decrypt-only | [legacy-ciphers.md](legacy-ciphers.md) |
| Platform-gap fallbacks (SHA-3/SHAKE, ChaCha20-Poly1305, verify-only RSA/ECDSA) | CAVP SHA-3/SHAKE 4,642/4,642, RFC 8439 all, Wycheproof with the fallback forced: ChaCha 316 (9 skipped), ECDSA 22,428 (4,880 skipped: SHA-224, SHAKE and Brainpool-224/320 curves), RSA PKCS#1 v1.5 9,826, PSS 4,788, 0 failures | n/a | strict DER ECDSA and exact-length RSA signatures on every platform | [fallbacks.md](fallbacks.md) |
| X.509, CSR, CRL, OCSP models | x509-limbo 30,377/30,379 certificates (2 refused with a typed error at the name-element limit), 18/18 CRLs, 0 differences from `X509Certificate2`; Wycheproof 5,701 signatures | OpenSSL 3.5.9 both directions: RSA, RSA-PSS, P-256, P-384, Brainpool, Ed25519, Ed448, ML-DSA, SLH-DSA (preview) | SLH-DSA and composite ML-DSA are preview while the platform API is experimental | [x509.md](x509.md) |
| Path validation (preview, under review) | x509-limbo 9,802 test cases with 3 documented deviations; NIST PKITS 245/247 (the 2 others use DSA, which is not verified); BetterTLS 9,572/9,572 | differential with `openssl verify` 3.5.9 and Go 1.26.8 `crypto/x509` over 19,357 cases: 441 differences, each class explained | the review's findings are being fixed; the validator is not yet recommended for trust decisions | [validation.md](validation.md), [validation-review.md](validation-review.md) |
| CMS | content types and recipient forms tested both ways where OpenSSL supports them | `openssl cms` 3.5.9 matrix: 169 passed, 0 failed, 20 skipped (EdDSA and ML-DSA without signed attributes, X25519/X448 key agreement and ML-KEM KEM recipients, which OpenSSL 3.5.9 cannot produce or open); CompressedData against OpenSSL 3.5.5 | X25519/X448 key agreement (RFC 8418) and KEMRecipientInfo (RFC 9629) are checked by our own reader and writer only; AuthEnvelopedData decryption buffers up to a limit | [cms.md](cms.md) |
| PKCS#8, PKCS#12, OpenSSH keys | PBES2/PBKDF2/scrypt, PBMAC1 (RFC 9579), legacy PKCS#12 PBEs (read) | OpenSSL 3.5.9 (`pkcs8`, `pkey`, `pkcs12`), the platform's PKCS#8/#12 export and import, `ssh-keygen` (keys, certificates, RFC 4716) | `chacha20-poly1305@openssh.com` key files and RC4 PKCS#12 PBEs are not read; ML-DSA/ML-KEM PKCS#8 is preview | [pkcs.md](pkcs.md) |
| `CryptoPolicy`, keys, two-phase signing | policy decisions per preset and rule | two-phase signatures and certificates verified by OpenSSL 3.5.9 | macOS login-keychain keys need an interactive session | [policy.md](policy.md), [keys.md](keys.md) |
| Issuer side: CA, CRLs and delta CRLs, RFC 3161 TSA and client messages, OCSP responder | profile, serial, status and nonce rules per RFC 5280 §5, 3161, 5816, 6960 | `openssl ts` 3.5.9 both ways (Ed25519 TSA keys ours only, OpenSSL cannot sign them), `openssl ocsp` 68/68, `openssl verify` and `crl -verify` for issued chains and CRLs | code-signing and S/MIME validity limits are our defaults | [issuance.md](issuance.md), [tsp.md](tsp.md), [ocsp-responder.md](ocsp-responder.md) |
| `Crypto.Load` | 159-file corpus (OpenSSL, `ssh-keygen`, platform exports), 0 misclassifications | n/a | OpenPGP, age and minisign files are not loaded yet | [load.md](load.md) |

## Speed

Ratio = OneCrypto time ÷ the fastest managed .NET library for the row (BouncyCastle 2.7.0; also `System.Formats.Asn1` for ASN.1), lower is faster. The bar is a geomean of at most 1.0 per area and no row above 1.25. Measured with BenchmarkDotNet on an AMD Ryzen 9 7950X3D (x64) and an Apple M2 (arm64), .NET 10. The x64 run shared the machine with other work and is marked load-flagged; it is repeated at the next release.

| Area | x64 | arm64 |
|---|---|---|
| Ed25519 sign / verify | 0.55 / 0.90 | 0.48 / 0.89 |
| Ed448 sign / verify | 0.52 / 0.61 | 0.71 / 0.94 |
| X25519 / X448 agreement | 0.76 / 0.50 | 0.77 / 0.74 |
| OCB, EAX (geomean) | 0.19 | 0.13 |
| AES key wrap | 1.53 (exception 2) | 0.32 |
| Argon2 / scrypt | 0.36 / 0.86 | 0.46 / 0.90 |
| Camellia CBC | 1.61 (exception 1) | 1.58 (exception 1) |
| ASN.1 certificate / 50k-element SEQUENCE (vs `AsnReader`) | 0.89 / 0.95 | 0.95 / 0.91 |
| X.509 parse / verify (geomean) | 0.36 / 0.84 | 0.38 / 0.31 |
| CMS sign / verify / envelope (geomean) | 0.18 / 0.33 / 0.47 | 0.34 / 0.18 / 0.10 |
| PKCS#12 load / PKCS#8 decrypt | 0.25 / 0.31 | 0.11 / 0.22 |

The curve span operations allocate nothing.

Documented exceptions to the bar:

1. **Camellia** encrypts at about 2.3–2.4× and decrypts at about 1.1× BouncyCastle. OneCrypto's Camellia never indexes a table with secret data (its S-box is computed with an AES instruction and nibble shuffles), while table-driven implementations leak through the cache. CBC encryption is a serial chain that parallel blocks cannot shorten.
2. **AES key wrap on x64** is 1.53×: RFC 3394 key wrap is a chain of dependent single-block AES calls, and the cost is the platform's per-call overhead; OneCrypto does not reimplement AES.
3. **ECDSA P-256 verification**, worst row: 1.70× for a certificate and 1.66× for a 1 KiB CMS message on x64 (1.16 and 1.15 on arm64). Verification calls the platform's ECDSA and is within 4% of the platform called directly; the area geomeans meet the bar.

## Robustness

Every parser has a fuzz target (`fuzz/`): asn1, pem, x509, ocsp, verify, cms, cmsenv, keys, pkcs8, pkcs12, ssh, validate, load, tsa, ocspresp. Each ran 600 s without a finding before this release (libFuzzer with SharpFuzz, one core each; 2.4 to 31 million executions per target). Every finding made during development is a committed regression test. Limits are on by default.

## Platforms

The per-platform availability of each algorithm (linux-x64 with OpenSSL 3.0 and 3.5, osx-arm64, browser-wasm) is generated by the test suite and checked so it cannot drift: [availability.md](availability.md). NativeAOT (linux-x64) and the browser (WebAssembly under Node) smoke apps run in CI.

## Constant time

Secret-handling code is written without secret-dependent branches, memory indices or early exits, and each secret-handling primitive has a dudect-style timing test (fixed-vs-random classes, Welch's t-test; [timing.md](timing.md)).

- **Secret data** (plaintext, ciphertext, messages): at 1,000,000 measurements per class on x64 and arm64, every target passes (max |t| at most 2.99 against a threshold of 4.5): AES-EAX, AES key wrap, Blowfish, Camellia-128 and -256. Earlier, shorter runs cover Ed25519/Ed448 signing, X25519/X448, OCB, CAST5, IDEA, Twofish, ChaCha20-Poly1305 and Argon2i. Results per primitive and machine are in [timing.md](timing.md).
- **Secret keys**: the measurement method for key-dependent timing does not yet pass its own fixed-vs-fixed control at that sample size, so no constant-time claim is made for key handling until it does.
- **Argon2id** uses data-dependent memory access after its first half-pass by design (RFC 9106 §3.4); only Argon2i is data-independent.

This library has not been independently audited.
