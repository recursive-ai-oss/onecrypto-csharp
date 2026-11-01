# `onecrypto sop` and the interoperability scoreboard

`onecrypto sop <subcommand>` implements the Stateless OpenPGP Command Line Interface (draft-dkg-openpgp-stateless-cli, version 16): exit codes, `--` handling, `@ENV:` and `@FD:` indirect inputs, and the `Armor`/`dearmor` rules of the draft. It is the harness the OpenPGP interoperability test suite drives, and a small command line in its own right.

## What works now

| Subcommand | State |
|---|---|
| `version` (`--backend`, `--extended`) | implemented; `--sopv` reports `UNSUPPORTED_OPTION` |
| `list-profiles generate-key`, `list-profiles encrypt` | `encrypt` answers `rfc9580` and `rfc4880`; `generate-key` answers no profile and exits 69 until that subcommand exists |
| `armor`, `dearmor` | implemented; labels are detected from the packets, input is read strictly, the operations are idempotent |
| `extract-cert` | implemented: a secret key becomes its certificate (RFC 9580 Appendix A.4 gives A.3 byte for byte) |
| `inline-detach` | implemented for binary and cleartext-signed messages |
| `sign`, `verify`, `inline-sign`, `inline-verify`, `encrypt`, `decrypt` | implemented, with `--as`, `--no-armor`, `--with-password`, `--with-key-password`, `--session-key-out`, `--with-session-key`, `--verifications-out`, `--not-before`/`--not-after`, `--profile`; value options take `--name=value` or `--name value` |
| `generate-key`, `change-key-password`, `revoke-key`, `update-key`, `merge-certs`, `certify-userid`, `validate-userid` | exit 69 (`UNSUPPORTED_SUBCOMMAND`) |

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

| Driver | Failure | IO | Neutral | Success |
|---|---|---|---|---|
| sqop 0.38.0 (Sequoia 2.4.1, nettle) | 72 | 0 | 537 | 1072 |
| gosop 1.1.0 (GopenPGP 3.0.0) | 99 | 0 | 537 | 1045 |
| onecrypto (this tool, x64, OpenSSL 3.0 platform without ML-KEM/ML-DSA) | 131 | 1 | 536 | 1013 |

The first run of the message subcommands scored 904 successes and 226 failures; the rest of the difference is fixes found by reading the failing cells (certificate evaluation, message grammar, unknown packets, armor, parser strictness).

**Cells where Sequoia succeeds and we do not: 69, all explained.**

| Cells | Test | Why |
|---|---|---|
| 60 | RSA key sizes (512 to 2047 bits, as primary key and subkey; sign, verify, encrypt, decrypt) | `CryptoPolicy.Standard` refuses RSA keys under 2048 bits for new data and for verification. Sequoia handles them under its own cut-offs. A caller who needs them passes a weaker policy. |
| 5 | Signature over the shattered SHA-1 collision | `Standard` flags SHA-1 data signatures made before 2031 (SP 800-131A dates) and accepts them with the flag; Sequoia rejects them. A `Strict` policy rejects them. |
| 4 | Encrypt-decrypt round trip with a v4 EdDSA/ECDH + ML-KEM-768+X25519 key | The platform of the run (OpenSSL 3.0) has no ML-KEM, so the message cannot be opened here: `AlgorithmNotSupportedException`, `sop` exit 13. Platforms with ML-KEM and ML-DSA run the post-quantum cells. |

The post-quantum message and signature cells score as failures on a platform without ML-KEM/ML-DSA (exit 13) and pass where the platform has them (RFC 9980 Appendix A is checked by unit tests there). The one remaining IO score is a LibrePGP version 5 secret key protected with OCB; it used to crash and now reports the key as not openable (LibrePGP v5 AEAD key protection is not implemented).

Cells where only GopenPGP succeeds, or where Sequoia and GopenPGP disagree about what the right answer is, are not listed: for example unknown packets before the literal data (Sequoia refuses, GopenPGP and the draft's text accept; we refuse), and signatures with the old signature-before-literal layout (GopenPGP accepts; Sequoia and we refuse).

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
