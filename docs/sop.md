# `onecrypto sop` and the interoperability scoreboard

`onecrypto sop <subcommand>` implements the Stateless OpenPGP Command Line Interface (draft-dkg-openpgp-stateless-cli, version 16): exit codes, `--` handling, `@ENV:` and `@FD:` indirect inputs, and the `Armor`/`dearmor` rules of the draft. It is the harness the OpenPGP interoperability test suite drives, and a small command line in its own right.

## What works now

| Subcommand | State |
|---|---|
| `version` (`--backend`, `--extended`) | implemented; `--sopv` reports `UNSUPPORTED_OPTION` |
| `list-profiles generate-key`, `list-profiles encrypt` | answers with no profile yet and exits 69 until those subcommands exist |
| `armor`, `dearmor` | implemented; labels are detected from the packets, input is read strictly, the operations are idempotent |
| `extract-cert` | implemented: a secret key becomes its certificate (RFC 9580 Appendix A.4 gives A.3 byte for byte) |
| `inline-detach` | implemented for binary and cleartext-signed messages |
| everything else (`generate-key`, `sign`, `verify`, `encrypt`, `decrypt`, `inline-sign`, `inline-verify`, `change-key-password`, `revoke-key`, `update-key`, `merge-certs`, `certify-userid`, `validate-userid`) | exits 69 (`UNSUPPORTED_SUBCOMMAND`) |

These are covered by in-process tests (`tests/OneCrypto.OpenPgp.Tests/SopTests.cs`).

## The scoreboard

The suite (OpenPGP interoperability test suite, pinned commit in `tools/oracles/interop-suite.sh`) is a black box: it is built, executed, and only its results are read. Every one of its tests has a producer and a consumer role that both go through sop, and nearly all of them need `generate-key`, `encrypt`, `sign` or `verify`. So none of the 251 tests exercises only the subcommands that exist today; our column is "unsupported" throughout, which is the expected state, and the drivers below show what a full column looks like.

Run it (on a machine with the oracles installed):

```
tools/oracles/interop-suite.sh                      # fetch, pin and build the suite (nettle and libclang user-locally)
tools/oracles/gosop.sh; tools/oracles/sequoia.sh    # driver oracles (the Sequoia sop driver is built by interop-suite.sh)
dotnet build -c Release src/OneCrypto.Cli
tools/oracles/interop-scoreboard.sh <path to onecrypto.dll> <output dir>
python3 tools/oracles/interop-summary.py <output dir>/results.json
```

The scoreboard script writes `config.json` for the drivers it finds, leaves out those that do not answer `version`, lists them in `missing.txt`, and writes `results.json` (the HTML report needs the suite's own working directory: run the suite with `--json-in` there).

### Latest run (251 tests, 14 sections, one score per driver per case)

| Driver | Failure | Neutral | Success | Unsupported |
|---|---|---|---|---|
| sqop 0.38.0 (Sequoia 2.4.1, nettle) | 72 | 531 | 1008 | 0 |
| gosop 1.1.0 (GopenPGP 3.0.0) | 99 | 531 | 981 | 0 |
| onecrypto (this tool) | 0 | 0 | 0 | 655 |

Left out: GnuPG (no sop driver ships with it), RNP (none packaged), OpenPGP.js (the published sop driver, `sop-openpgp-js` 0.1.1, bundles OpenPGP.js 4 and does not start on the pinned Node.js 26; a driver over OpenPGP.js 6 is not written yet). They are covered at the file level by the corpus below.

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
