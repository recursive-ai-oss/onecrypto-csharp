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
| Path validation (preview, internal review done) | x509-limbo 9,802 test cases with 3 documented deviations; NIST PKITS 245/247 (the 2 others use DSA, which is not verified); BetterTLS 9,572/9,572 | differential with `openssl verify` 3.5.9 and Go 1.26.8 `crypto/x509` over 19,357 cases: 441 differences, each class explained | internal review (not an external audit): all 8 findings and observations O1–O5 and O7 fixed, O6 (report contents only) open; still a preview, so not yet recommended for trust decisions | [validation.md](validation.md), [validation-review.md](validation-review.md) |
| CMS | content types and recipient forms tested both ways where OpenSSL supports them | `openssl cms` 3.5.9 matrix: 169 passed, 0 failed, 20 skipped (EdDSA and ML-DSA without signed attributes, X25519/X448 key agreement and ML-KEM KEM recipients, which OpenSSL 3.5.9 cannot produce or open); CompressedData against OpenSSL 3.5.5 | X25519/X448 key agreement (RFC 8418) and KEMRecipientInfo (RFC 9629) are checked by our own reader and writer only; AuthEnvelopedData decryption buffers up to a limit | [cms.md](cms.md) |
| PKCS#8, PKCS#12, OpenSSH keys | PBES2/PBKDF2/scrypt, PBMAC1 (RFC 9579), legacy PKCS#12 PBEs (read) | OpenSSL 3.5.9 (`pkcs8`, `pkey`, `pkcs12`), the platform's PKCS#8/#12 export and import, `ssh-keygen` (keys, certificates, RFC 4716) | `chacha20-poly1305@openssh.com` key files and RC4 PKCS#12 PBEs are not read; ML-DSA/ML-KEM PKCS#8 is preview | [pkcs.md](pkcs.md) |
| `CryptoPolicy`, keys, two-phase signing | policy decisions per preset and rule | two-phase signatures and certificates verified by OpenSSL 3.5.9 | macOS login-keychain keys need an interactive session | [policy.md](policy.md), [keys.md](keys.md) |
| Issuer side: CA, CRLs and delta CRLs, RFC 3161 TSA and client messages, OCSP responder | profile, serial, status and nonce rules per RFC 5280 §5, 3161, 5816, 6960 | `openssl ts` 3.5.9 both ways (Ed25519 TSA keys ours only, OpenSSL cannot sign them), `openssl ocsp` 68/68, `openssl verify` and `crl -verify` for issued chains and CRLs | code-signing and S/MIME validity limits are our defaults | [issuance.md](issuance.md), [tsp.md](tsp.md), [ocsp-responder.md](ocsp-responder.md) |
| `RecursiveAI.OneCrypto.Online`: guarded transport, cache, RFC 3161, OCSP, CRL and AIA clients | record/replay fixtures for every client; SSRF guard cases (loopback, private, link-local, carrier-grade NAT, multicast, IPv4-wrapping IPv6, checked on the connected address and on every redirect) | OpenSSL 3.5.9 `ts`/`ocsp` 11 cases; a live run against public TSAs and a public CA's OCSP, CRL and AIA endpoints | revocation is fetched only after a path is chosen; nothing is fetched unless a call asks, and offline revocation stays unknown | [online.md](online.md) |
| `RecursiveAI.OneCrypto.Pdf`: PAdES B-B to B-LTA on OnePDF 1.17.1 | OnePDF's PDF signature attack corpus through the bridge: 117 comparisons, 0 disagreements with OnePDF's own verdict; certification (DocMDP) levels with document time-stamps | `openssl cms`/`ts` 3.5.9 on the embedded CMS and time-stamps; poppler `pdfsig` 26.01.0 agrees for RSA and ECDSA signatures (it reports every EdDSA and ML-DSA signature as invalid, including those made by other PDF signers, so it is not an oracle for them); **Adobe Acrobat Reader** 2026.002.22031 (Windows, test root trusted): RSA B-LT/B-LTA, RSA-PSS B-LTA and ECDSA P-256 B-B/B-T/B-LT/B-LTA signatures valid, document time-stamps valid with LTV, the tampered control reported as altered; **two first-set files differ and are open:** RSA B-B ("validity unknown": no revocation evidence) and RSA B-T ("errors in the formatting"; every signature, token and certificate in it is strict DER, it verifies with `openssl cms`, and the same structure with other values is accepted, so the cause is not an encoding defect we can find without the reader; a second set separates the remaining hypotheses); Ed25519 is not supported by Reader (ISO/TS 32002), though the Ed25519 B-LTA document time-stamp is valid | EdDSA and ML-DSA signatures are judged by the bridge alone (OnePDF does not check them); ML-DSA is a preview | [pdf.md](pdf.md) |
| OpenPGP packets and armor (`RecursiveAI.OneCrypto.OpenPgp`) | every packet of RFC 9580 §5 with versions 3 to 6 of keys and signatures, RFC 9980 key and PKESK formats; RFC 9580 Appendix A and RFC 9980 Appendix A samples; a corpus of keys, certificates, signatures and messages written by GnuPG 2.4.4, 2.4.8 and 2.5.24, Sequoia `sq` 1.5.0, RNP 0.17.0, OpenPGP.js 6.3.2 and gosop 1.1.0: every file parses and writes back byte for byte; interoperability suite section "Packet parser": 48 successes, no failures | fingerprints agree with each tool's own listing | LibrePGP version 5 is read, never generated | [openpgp.md](openpgp.md) |
| OpenPGP messages: sign, verify, encrypt, decrypt, cleartext, streaming | RFC 9580 Appendix A (inline, cleartext, detached, OCB/EAX/GCM, Argon2 SKESK), RFC 9980 Appendix A.1–A.4, GnuPG-written messages in every legacy cipher, old SED, bzip2 and zlib; the interoperability suite through `onecrypto sop` ([sop.md](sop.md)): 251 tests | two-way through `sop` on the merged tree: GnuPG 2.4.8 42/0 and 2.5.24 42/0, RNP 0.17.0-3 54/0, Sequoia `sqop` 0.38.0 62/0, `gosop` 1.1.0 (GopenPGP 3.0.0) 81/0, OpenPGP.js 6.3.2 72/0 with 4 not supported by it (passed/failed). Streaming at 1 GiB: peak resident set 51,112 KiB to encrypt, 99,664 KiB to decrypt, 41,236 KiB to inline-sign and 43,724 KiB to inline-verify, against 43,916, 100,688, 40,812 and 43,524 KiB at 128 MiB | **RFC 9580 §12.4**: the library verifies with RSA keys of 1024 to 2047 bits (flagged, `key.rsa.weak-from`) and does not look at the size of a certifying primary key; it decrypts with a weak RSA key without a warning. 59 interoperability cells where Sequoia succeeds and we do not ([sop.md](sop.md)); GnuPG 2.5.24 does the same operation in 56 of them and cannot in 3 for a technical reason. **RSA PKCS#1 v1.5 key transport:** a bad padding and a bad checksum differ by timing (|t| 40.9, the platform's RSA throws); no constant-time claim. Kyber PKESK over NIST or Brainpool curves: `AlgorithmNotSupportedException` | [openpgp.md](openpgp.md), [sop.md](sop.md), [decryption-review.md](decryption-review.md) |
| OpenPGP keys: generation, edits, revocation, certification, secret-key protection, two-phase signing | every profile with and without a password through signing, encryption, revocation, certification and password change; suite sections "Key Generation" (205 successes, no failures) and "Revocations" (88 successes, no failures) | passed/failed/not applicable: GnuPG 2.4.8 121/0/8, GnuPG 2.5.24 113/0/16, RNP 0.17.0-3 93/0/4, `sqop` 302/0/6, `gosop` 237/0/83, OpenPGP.js 272/0/48 (cells the other side cannot run are not applicable). Three-process two-phase signing verified by us, `sqop` and GnuPG 2.5.24: 46/0; GnuPG 2.4.8: 36/0 | n/a causes are the oracle's (version 6 keys, native Ed25519, unprotected ECDH subkeys in 2.5, a terminal prompt in the 2.5 build's `--gen-revoke`, no `update-key` in `gosop`), see openpgp.md | [openpgp.md](openpgp.md) |
| LibrePGP (read in full; written only for recipients that need it) | draft-koch-librepgp-06: version 5 keys and signatures, OCB Encrypted Data, SKESK v5, Kyber keys read; GnuPG-made fixtures | GnuPG 2.4.8 31/0 (2 skipped: no RNP in that run); GnuPG 2.5.24 with RNP 0.17.0-3: 34/0 (7 skipped: the 2.5.24 oracle build writes no bzip2, RNP does not import version 5 keys); our OCB messages open in GnuPG 2.5.24 | Sequoia cannot read OCB Encrypted Data, so the 3 production cells with version 5 keys score Failure for us (GnuPG writes and reads the same container); Kyber over NIST/Brainpool curves is not supported | [openpgp.md](openpgp.md) |
| GnuPG home and cert-d | `pubring.kbx` 45/45, key files 126/126, legacy rings and ownertrust of GnuPG 2.2.45, 2.4.4, 2.4.8 and 2.5.24 homes, cert-d 13/13 | `gpg` signature and decryption checks 8/8 with 2.4.8 and 2.5.24 (re-run on the merged tree: pass), Sequoia `sq` 1.5.0 lists, merges and waits on our lock 4/4 (re-run: pass) | unsettled keybox fields are listed in the document; an update that only adds unhashed subpackets is not merged | [gnupg-home.md](gnupg-home.md) |
| OpenPGP trust: classic and flow models | 162 generated scenarios (90 classic, 72 flow), 30 of each random; 10,000-node graph within limits | classic model against `gpg --with-colons` 2.4.8 and 2.5.24, flow model against `sq pki authenticate` 1.5.0: 162 of 162 agree or are the two documented deviations below | deviations: a revoked or expired ultimate key vouches for nothing here and a certification dated after the reference time is ignored (GnuPG scenarios c44 and c27) | [openpgp-trust.md](openpgp-trust.md) |
| Key discovery: WKD, HKP, VKS (`.Online`) and `KeyDiscovery` | the drafts' examples; recorded WKD (both methods, missing policy, 404), HKP and VKS exchanges; filtering of hostile key responses | 5 of 5 opt-in live checks (WKD, HKP and VKS endpoints, about 14 requests); no HKP server was available as an oracle | HKP version 1 only; the live checks never run in CI | [online.md](online.md) |
| Autocrypt Level 1 | the specification's examples (setup message, header values, gossip) | GnuPG 2.4.8 opens the specification's setup message and ours, and we open one it makes (the 2.5.24 oracle build lacks zlib and cannot open the specification's message); no Autocrypt client was available as an oracle | header handling and peer-state rules are tested against the specification's text and our own round trips | [autocrypt.md](autocrypt.md) |
| Browser (WebAssembly) | the browser suite in headless Chromium (Chrome for Testing 156.0.8078.80): 13 areas, including 920 Wycheproof signature verifications, 153 x509-limbo validations and 778 certificates; compared case by case with Node and a native run, 1,940 cases, 0 differences | n/a | the browser runtime has no AES, so encrypted PKCS#8, PKCS#12 and OpenSSH keys cannot be opened there (typed `AlgorithmNotSupportedException`) | [browser.md](browser.md) |
| `Crypto.Load` | 159-file corpus (OpenSSL, `ssh-keygen`, platform exports), 0 misclassifications | n/a | OpenPGP, age and minisign files are not loaded yet | [load.md](load.md) |

## Release gate run (0.3)

Run on one tree on a 32-core Linux x64 machine (.NET 10.0.402), with the oracles pinned in the repository's tool scripts. The suite ran twice, as hosted CI does with the system OpenSSL 3.0.13 and with OpenSSL 3.5.9, which has ML-KEM and ML-DSA.

| Project | OpenSSL 3.0.13 (total / passed / failed / skipped) | OpenSSL 3.5.9 |
|---|---|---|
| `OneCrypto.Tests` | 1405 / 1312 / 0 / 93 | 1407 / 1366 / 0 / 41 |
| `OneCrypto.OpenPgp.Tests` | 713 / 686 / 0 / 27 | 719 / 705 / 0 / 14 |
| `OneCrypto.Online.Tests` | 305 / 296 / 0 / 9 | 305 / 296 / 0 / 9 |
| `OneCrypto.Pdf.Tests` | 165 / 159 / 0 / 6 | 165 / 162 / 0 / 3 |

The OpenPGP counts on 3.5.9 include the 6 tests added for the two fixes of this run; the OpenSSL 3.0 column ran before them. What the skips are:

- **Opt-in runs** (all platforms): the live public-endpoint checks (`ONECRYPTO_ONLINE_LIVE`, 9 in `.Online`), the million-iteration and 1–2 GiB vectors (`ONECRYPTO_LONG_VECTORS`, `ONECRYPTO_BIG_VECTORS`: 6), the two large streaming checks of CMS (`ONECRYPTO_STREAM_BYTES`; the OpenPGP 1 GiB runs are in the table above), the validator differential (`ONECRYPTO_DIFF_CASES`), the PDF corpus, Acrobat sample-set and DER-walk directories (3 in `.Pdf`), and the tests that need `ONECRYPTO_GPG` or `ONECRYPTO_SQ` (13 in `.OpenPgp`). With `gpg` 2.5.24 and `sq` 1.5.0 supplied, the OpenPGP project runs 711 passed and 1 failed: the specification's Autocrypt setup message does not open in the 2.5.24 oracle build, which was built without zlib; with `gpg` 2.4.8 the Autocrypt tests pass (32 of 32).
- **What OpenSSL 3.5.9 cannot do** (31 in the core project): sign or open CMS forms without signed attributes for EdDSA and ML-DSA, X25519 and X448 key agreement and ML-KEM recipients, `ts -reply` with an Ed25519 key, CompressedData (it was built without zlib). Those forms are covered by our own reader and writer.
- **Platform**: the one test that needs a platform without AES-CCM.
- **OpenSSL 3.0 only**: tests that need ML-KEM or ML-DSA (and `openssl` features of 3.5) skip rather than fail: 52 in the core project, 13 in `.OpenPgp`, 3 in `.Pdf`.

**Platform smokes** on the same tree: NativeAOT publish for linux-x64 with warnings as errors, no trim or AOT warning, and the smoke app runs (including key discovery and Autocrypt); the browser-wasm smoke app runs under Node and its availability table matches [availability.md](availability.md); the browser suite in headless Chromium (Chrome for Testing 156.0.8078.80) passes 1,940 cases in 13 areas, with 0 differences against Node and 0 in the judged areas against a native run (17 expected platform differences: the browser has no AES, and uses the managed RSA, ECDSA and SHA-3 fallbacks).

**Interoperability scoreboard**: [sop.md](sop.md#the-scoreboard).

## Speed

Ratio = OneCrypto time ÷ the fastest managed .NET library for the row (BouncyCastle 2.7.0; also `System.Formats.Asn1` for ASN.1), lower is faster. The bar is a geomean of at most 1.0 per area and no row above 1.25. Measured with BenchmarkDotNet on an AMD Ryzen 9 7950X3D (x64) and an Apple M2 (arm64), .NET 10. The x64 runs shared the machine with other work and are marked load-flagged (the x64 validation row is indicative); they are repeated at the next release. Path validation is also reported against the platform's offline `X509Chain`, which calls native code: 1.21 on x64 (indicative), not part of the bar.

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
| Certificate parse + path validation (geomean; worst row) | 0.80, indicative | 0.56; 0.57 |

The curve span operations allocate nothing.

Documented exceptions to the bar:

1. **Camellia** encrypts at about 2.3–2.4× and decrypts at about 1.1× BouncyCastle. OneCrypto's Camellia never indexes a table with secret data (its S-box is computed with an AES instruction and nibble shuffles), while table-driven implementations leak through the cache. CBC encryption is a serial chain that parallel blocks cannot shorten.
2. **AES key wrap on x64** is 1.53×: RFC 3394 key wrap is a chain of dependent single-block AES calls, and the cost is the platform's per-call overhead; OneCrypto does not reimplement AES.
3. **ECDSA P-256 verification**, worst row: 1.70× for a certificate and 1.66× for a 1 KiB CMS message on x64 (1.16 and 1.15 on arm64). Verification calls the platform's ECDSA and is within 4% of the platform called directly; the area geomeans meet the bar.

## Robustness

Every parser has a fuzz target (`fuzz/`). All 27 targets ran 600 s each on the release tree, libFuzzer with SharpFuzz, up to four in parallel with their own work directories, with no crash, hang or memory blow-up. Every finding made during development is a committed regression test. Limits are on by default.

| Target | Executions | Coverage features | | Target | Executions | Coverage features |
|---|---|---|---|---|---|---|
| asn1 | 21,778,219 | 7,471 | | pgppacket | 13,372,923 | 9,412 |
| pem | 31,343,493 | 1,612 | | pgpmessage | 429,262 | 9,088 |
| x509 | 16,153,774 | 9,865 | | pgpkey | 397,140 | 7,444 |
| ocsp | 24,868,637 | 4,864 | | gnupghome | 15,083,459 | 8,821 |
| ocspresp | 19,943,086 | 5,260 | | bzip2 | 1,879,150 | 891 |
| cms | 6,632,979 | 16,172 | | trust | 945,693 | 12,791 |
| cmsenv | 3,207,394 | 10,989 | | autocrypt | 1,952,190 | 8,094 |
| keys | 25,112,777 | 4,038 | | hkpindex | 12,833,637 | 6,460 |
| verify | 3,515,038 | 419 | | pkcs8 | 20,216,515 | 4,254 |
| validate | 9,041,837 | 14,655 | | pkcs12 | 15,889,943 | 4,766 |
| load | 9,362,285 | 8,929 | | ssh | 2,387,628 | 2,596 |
| tsa | 16,360,464 | 9,776 | | phc | 24,043,010 | 283 |
| online | 10,750,410 | 12,501 | | pades | 343,995 | 37,876 |
| placeholder | 1,143,809 | 16,697 | | | | |

The slowest targets are the ones that build keys or whole messages (`pgpkey`, `pgpmessage`, `pades`). `pgpmessage` and `pgpkey` were run again for 600 s each on the final tree, after the two small OpenPGP fixes of this release (the padded ECDH value and the RSA size check on encryption), with no crashes; the numbers above are from that run.

## Platforms

The per-platform availability of each algorithm (linux-x64 with OpenSSL 3.0 and 3.5, osx-arm64, browser-wasm) is generated by the test suite and checked so it cannot drift: [availability.md](availability.md). NativeAOT (linux-x64, osx-arm64) and the browser (WebAssembly under Node, and the browser suite in headless Chromium) run in CI.

## Constant time

Secret-handling code is written without secret-dependent branches, memory indices or early exits, and each secret-handling primitive has a dudect-style timing test (fixed-vs-random classes, Welch's t-test; [timing.md](timing.md)).

- **Secret data** (plaintext, ciphertext, messages): at 1,000,000 measurements per class on x64 and arm64, every target passes (max |t| at most 2.99 against a threshold of 4.5): AES-EAX, AES key wrap, Blowfish, Camellia-128 and -256. Earlier, shorter runs cover Ed25519/Ed448 signing, X25519/X448, OCB, CAST5, IDEA, Twofish, ChaCha20-Poly1305 and Argon2i. Results per primitive and machine are in [timing.md](timing.md).
- **Secret keys**: the method now uses a fresh key object per measurement and a fixed-vs-fixed control for every key target. At 1,000,000 measurements on arm64 every key target that completed, and its control, passes (max |t| 2.86), but most of those runs shared the machine with other work and one group did not finish in its time slot, so no constant-time claim is made for key handling until a run on a quiet machine passes on both x64 and arm64.
- **Argon2id** uses data-dependent memory access after its first half-pass by design (RFC 9106 §3.4); only Argon2i is data-independent.

This library has not been independently audited.
