# `onecrypto sop` and the interoperability scoreboard

`onecrypto sop <subcommand>` implements the Stateless OpenPGP Command Line Interface (draft-dkg-openpgp-stateless-cli, version 16): exit codes, `--` handling, `@ENV:` and `@FD:` indirect inputs, and the `Armor`/`dearmor` rules of the draft. It is the harness the OpenPGP interoperability test suite drives, and a small command line in its own right.

## What works now

| Subcommand | State |
|---|---|
| `version` (`--backend`, `--extended`, `--sop-spec`, `--sopv`) | implemented; `--sopv` answers `1.2` |
| `list-profiles generate-key`, `list-profiles encrypt` | `encrypt` answers `rfc9580` and `rfc4880`; `generate-key` lists `default`, `rfc9580`, `rfc9580-v4`, `rfc9580-ed448`, `rfc9580-rsa`, `rfc4880` (alias `compatibility`), `draft-koch-eddsa-for-openpgp-00`, `nist-p256`, `nist-p384`, `nist-p521`, `security`, `performance`, `pqc` and `pqc-high` |
| `armor`, `dearmor` | implemented; labels are detected from the packets, input is read strictly, the operations are idempotent |
| `extract-cert` | implemented: a secret key becomes its certificate (RFC 9580 Appendix A.4 gives A.3 byte for byte) |
| `inline-detach` | implemented for binary and cleartext-signed messages |
| `sign`, `verify`, `inline-sign`, `inline-verify`, `encrypt`, `decrypt` | implemented, with `--as`, `--no-armor`, `--with-password`, `--with-key-password`, `--session-key-out`, `--with-session-key`, `--verifications-out`, `--not-before`/`--not-after`, `--profile`; value options take `--name=value` or `--name value` |
| `generate-key` (`--profile`, `--signing-only`, `--with-key-password`, `--no-armor`) | implemented; version 4 and 6 keys only, never version 5 |
| `change-key-password` | implemented; every secret key packet is unlocked with one of the `--old-key-password` values (`KEY_IS_PROTECTED` otherwise) and written again under `--new-key-password`, or unprotected |
| `revoke-key` | implemented; the output is the public certificate with a hard key revocation (reason "no reason given") |
| `certify-userid` | implemented; `--userid` (repeatable), `--no-require-self-sig`, `CERT_USERID_NO_MATCH` (107) and `KEY_CANNOT_CERTIFY` (109) as in the draft |
| `validate-userid` | implemented; `--addr-spec-only`, `--validate-at`; `CERT_USERID_NO_MATCH` when a certificate on standard input is not certified by any authority |
| `merge-certs` | implemented; also accepts the bare revocation signature that `gpg --gen-revoke` writes, applied to the certificate it revokes |
| `update-key` | implemented; re-issues the self-signatures, drops weak preferences, adds an encryption subkey unless `--signing-only`, merges `--merge-certs`; the primary key is never changed; `--revoke-deprecated-keys` has no effect because no replacement key is ever made; a revoked primary key is `PRIMARY_KEY_BAD` (103) |
| `onecrypto sopv` | the sopv subset: `version`, `verify`, `inline-verify` and `validate-userid`; every other subcommand answers 69 |

`encrypt` chooses the container from the recipients' keys (see [openpgp.md](openpgp.md#messages)): SEIPD v2 for keys that read it, LibrePGP OCB Encrypted Data for version 5 keys and keys announcing it, SEIPD v1 otherwise; `--profile=rfc4880` forces SEIPD v1. `decrypt` also reads GnuPG 2.5's Kyber keys (X25519 and X448) and bzip2-compressed messages.

An algorithm the platform lacks (for example ML-DSA or ML-KEM on an OpenSSL without them) exits 13 (`UNSUPPORTED_ASYMMETRIC_ALGO`). The subcommands are covered by in-process tests (`tests/OneCrypto.OpenPgp.Tests/SopTests.cs`) and the two-way scripts in `tools/oracles/` (`gpg-messages.sh`, `rnp-messages.sh`, `sop-matrix.sh`).

## The scoreboard

The suite (OpenPGP interoperability test suite, pinned commit in `tools/oracles/interop-suite.sh`) is a black box: it is built, executed, and only its results are read. Every test has a producer and a consumer role that both go through sop. Round-trip cases start with `generate-key`, which this tool does not provide yet, so they cannot use it as the producer; every other case runs with us as the consumer of what Sequoia, GopenPGP and the test data produced.

Run it (on a machine with the oracles installed):

```
tools/oracles/interop-suite.sh                      # fetch, pin and build the suite (nettle and libclang user-locally)
tools/oracles/gosop.sh; tools/oracles/sequoia.sh    # driver oracles (the Sequoia sop driver is built by interop-suite.sh)
dotnet build -c Release src/OneCrypto.Cli
tools/oracles/interop-scoreboard.sh <path to onecrypto.dll> <output dir>
python3 tools/oracles/interop-summary.py <output dir>/results.json
python3 tools/oracles/interop-vs-sqop.py <output dir>/results.json   # cells Sequoia passes and we fail
```

`interop-show.py` and `interop-dump.py` show or extract one cell so the command can be repeated by hand.

The scoreboard script writes `config.json` for the drivers it finds, leaves out those that do not answer `version`, lists them in `missing.txt`, and writes `results.json` (the HTML report needs the suite's own working directory: run the suite with `--json-in` there).

### Latest run (251 tests, 14 sections, one score per driver per case)

Run on the release tree, twice: on a platform with ML-KEM and ML-DSA (OpenSSL 3.5.9) and on one without (OpenSSL 3.0.13, as hosted CI has). The suite reports four scores here, Success, Failure, Neutral and Unknown; no IO score appears. "Unknown" is the suite's verdict when the producer chose another algorithm than the one under test (9 cells, below).

| Driver | Platform | Failure | Neutral | Success | Unknown |
|---|---|---|---|---|---|
| sqop 0.38.0 (Sequoia 2.4.1, nettle) | with ML-KEM/ML-DSA | 108 | 554 | 1193 | 0 |
| gosop 1.1.0 (GopenPGP 3.0.0) | with ML-KEM/ML-DSA | 136 | 554 | 1165 | 0 |
| onecrypto (this tool, x64) | with ML-KEM/ML-DSA | 110 | 554 | 1182 | 9 |
| sqop 0.38.0 | without | 72 | 554 | 1193 | 0 |
| gosop 1.1.0 | without | 100 | 554 | 1165 | 0 |
| onecrypto | without | 119 | 554 | 1137 | 9 |

On the platform with ML-KEM and ML-DSA our driver generates the post-quantum profiles, so `sqop` and `gosop` each fail 36 more cells there, in which our post-quantum keys and messages are consumed by them (`sqop`'s nettle build has no ML-KEM or ML-DSA at all; the `gosop` failures were not investigated). Our own 9 extra failures on the platform without ML-KEM and ML-DSA are the post-quantum message and signature cells, which exit 13 there.

**Cells where Sequoia succeeds and we do not: 59 on both platforms, none unexplained.** The platform without ML-KEM/ML-DSA adds no cell to this list.

| Cells | Test | Why |
|---|---|---|
| 36 | RSA key sizes, **primary key** 512 to 2047 bits (signing, verification, encryption, decryption; 9 sizes each) | The suite's keys have a weak RSA primary key that certifies a 3072-bit subkey. We accept the certificate: the library does not apply an RSA size limit to the key that certifies, only to the key that signs, encrypts or decrypts (a gap against RFC 9580 §12.4, "MUST NOT encrypt, sign, or verify using RSA keys of a size less than 2048 bits", which Sequoia follows). GnuPG 2.5.24 does what we do: it verifies, encrypts, signs and decrypts with these keys at every size (checked on the suite's artifacts), apart from the size 1025 for the secret-key operations (below). |
| 6 | RSA key sizes, **subkey** 1024 to 2047 bits, verification | `CryptoPolicy.Standard` verifies with RSA keys of 1024 bits and more and flags those under 2048 from 2014 (SP 800-131A); it refuses smaller keys (the 512, 768 and 1023-bit cells pass). RFC 9580 §12.4 says MUST NOT under 2048; Sequoia follows it. GnuPG 2.5.24 verifies all 6. `CryptoPolicy.Strict` refuses them. |
| 9 | RSA key sizes, **subkey** 512 to 2047 bits, decryption | The expected result is a warning or a failure (SHOULD warn under 3072 bits); we decrypt without a warning. GnuPG 2.5.24 decrypts 8 of the 9 without a warning. |
| 5 | Signature over the shattered SHA-1 collision | `Standard` flags SHA-1 data signatures made before 2031 (SP 800-131A dates) and accepts them with the flag; Sequoia rejects them. GnuPG 2.5.24 verifies all of them as good. A `Strict` policy rejects them. |
| 3 | Production with a version 5 key that announces AEAD (OCB), AES-128, -192 and -256 | We write the LibrePGP OCB Encrypted Data container for such a recipient; Sequoia cannot read it (`sqop` answers "Invalid data type"), and the suite scores the producer by whether Sequoia opens the message. GnuPG 2.5.24 opens all three of ours with their session keys, and writes the same container itself. Sequoia and GnuPG disagree here. |

**Cells where Sequoia and GnuPG agree and we fail: none.** GnuPG is not a driver of the suite, so each class was run against GnuPG 2.5.24 by hand on the suite's own artifacts (`gpg --verify`, `--encrypt`, `--decrypt`, `--sign`). Of the 36 + 9 secret-key cells the only ones GnuPG does not do are the 3 with a 1025-bit RSA key (primary key decryption, subkey decryption and primary key signing): its agent does not import that secret key ("No secret key"), a limitation of its key import, not a policy decision, while Sequoia refuses on policy and we perform the operation. We list them here instead of counting them as agreement.

The nine "Unknown" cells (Symmetric Encryption Algorithm support, production side, OCB with a version 5 key that lists IDEA, TripleDES, CAST5 or Blowfish): the suite asks for a message under an algorithm that cannot be used with OCB; we use AES-128 with OCB, `sqop` and `gosop` write SEIPD version 1 ("Producer did not use AEAD"), which the suite accepts.

The list documented before this run had 69 cells (60 RSA, 5 SHA-1, 4 ML-KEM). On the merged tree it first came to 72: the 3 version 5 cells above were new with the LibrePGP writer, and the 4 ML-KEM cells ("Encrypt-Decrypt roundtrip with v4 EdDSA/ECDH,ML-KEM-768+X25519 key") had been put down to the platform but also failed on OpenSSL 3.5.9. That was a defect, with another one beside it, both fixed in this run: Sequoia pads the wrapped ECDH value to 40 octets (21 padding octets for AES-128), which RFC 9580 §11.5 allows, and we accepted 8 octets of padding at most; and we encrypted to RSA keys under the policy's size for new data (RFC 9580 §12.4), which removed the 9 "subkey, encryption" cells. Cells where only GopenPGP succeeds, or where Sequoia and GopenPGP disagree about what the right answer is, are not listed: for example unknown packets before the literal data (Sequoia refuses, GopenPGP and the draft's text accept; we refuse), and signatures with the old signature-before-literal layout (GopenPGP accepts; Sequoia and we refuse).

Reproduce: `tools/oracles/interop-scoreboard.sh` (once per OpenSSL), then `interop-summary.py` and `interop-vs-sqop.py` on `results.json`.

Left out of the scoreboard: GnuPG (no sop driver ships with it), RNP (none packaged), OpenPGP.js (the published sop driver, `sop-openpgp-js` 0.1.1, bundles OpenPGP.js 4 and does not start on the pinned Node.js 26; a driver over OpenPGP.js 6 is not written yet). They are covered by the two-way scripts and the corpus below.

## Corpus

`tools/oracles/corpus-*.sh` and `tools/oracles/pgpjs6/corpus.mjs` generate keys, certificates, signatures and messages with throwaway keys; `CorpusTests` (set `ONECRYPTO_OPENPGP_CORPUS`) parses every file, checks that writing it back is byte-identical (from memory and through the stream reader), and compares fingerprints with each tool's own listing (primary key first, subkeys as a set).

| Source | Keys | Certs | Signatures | Messages |
|---|---|---|---|---|
| GnuPG 2.4.4 | 46 | 44 | 3 | 39 (+1 cleartext skipped) |
| GnuPG 2.4.8 | 42 | 40 | 3 | 37 (+1) |
| GnuPG 2.5.24 | 46 | 44 | 3 | 38 (+1) |
| Sequoia sq 1.5.0 | 20 | 10 | 20 | 51 (+10) |
| RNP 0.17.0 | 5 | 5 | 10 | 40 (+5) |
| OpenPGP.js 6.3.2 | 24 | 16 | 16 | 88 (+8) |
| gosop 1.1.0 (GopenPGP 3.0.0) | 8 | 8 | 8 | 20 (+4) |

Every file parses and rewrites identically. Two oracle behaviours are handled in the test, not the parser: gosop appends a line feed to a binary inline-signed message (trimmed, 4 files), and GnuPG writes LibrePGP version 5 keys (Ed448, Kyber) whose secret-key layout is read per the LibrePGP draft. Cleartext-signed messages are not binary OpenPGP data and are skipped.

Post-quantum samples come from Sequoia's `mldsa65-ed25519` and `mldsa87-ed448` suites (RFC 9980) and GnuPG 2.5's Kyber keys (LibrePGP); the pinned RNP and OpenPGP.js were not driven for post-quantum keys.
