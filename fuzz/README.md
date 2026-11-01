# Fuzzing

One executable (`fuzz/OneCrypto.Fuzz`) holds one target per input surface. SharpFuzz instruments `RecursiveAI.OneCrypto.dll`; libFuzzer drives it.

| Target | Input | Surface |
|---|---|---|
| `asn1` | a rules/mode byte, then ASN.1 bytes | the span reader over every type, the element model, the stream reader and its OCTET STRING stream, BER-to-DER |
| `pem` | a mode byte, then text | strict and lax PEM parsing and write/parse round trip |
| `cms` | a mode byte, then a CMS blob (or, with mode bits `10`, a time-stamp response) | BER-to-DER conversion, CMS SignedData parsing, signer verification with chain building, streamed verification and streaming decompression with their async twins, time-stamp response checks |
| `x509` | a structure byte, then its encoding | certificates, CRLs and their entries, certification requests, attribute certificates, every typed extension value (parse, encode, parse again), names, general names, public keys with signature checks |
| `cmsenv` | a content-type byte, then a ContentInfo | EnvelopedData, AuthEnvelopedData, AuthenticatedData, EncryptedData, DigestedData and CompressedData parsed and opened with fixed keys; streamed decryption and verification, each with its async twin required to reach the same verdict and the same plaintext |
| `tsa` | a structure byte, then octets | the time-stamp authority handler end to end (every granted token must verify against its own request), and the time-stamp request, response and TSTInfo parsers |
| `ocspresp` | a structure byte, then octets | the OCSP responder handler end to end, CA-signed and delegated (every successful response must verify and echo the request), and the CA's certification request path |
| `ocsp` | a structure byte, then its encoding | OCSP requests, responses, basic responses and CertIDs, with signature checks against embedded certificates |
| `keys` | a serialised two-phase signing state | `PreparedSignature` and `PreparedSignedData` decode, re-encode identity and signature checks against whatever decodes |
| `pkcs8` | a structure byte, then bytes or PEM text | PrivateKeyInfo with every key conversion, EncryptedPrivateKeyInfo with decryption under tight cost caps, legacy and PKCS#8 PEM private keys |
| `pkcs12` | a PFX | structure, MAC check (both kinds), decryption of every safe, every bag type |
| `ssh` | a structure byte, then bytes or text | OpenSSH public keys (blob, authorized_keys line, RFC 4716 text), certificates with signature check, private key files with a bcrypt round cap |
| `load` | a file as `Crypto.Load` takes it | the sniffing table and every container parser behind it (PEM, DER/BER, PKCS#8, PKCS#12, PKCS#7 bags, OpenSSH, X.509 objects), with a password callback that always answers |
| `pades` | a signed PDF with its document security store and time-stamps, behind a header carrying the reference time and the trust anchor | OnePDF's parser, the signature layout checks, the store reader, the CMS and time-stamp verifiers and the path validator behind `PadesVerifier`; a result must never be `bridge-error` and never more lenient than OnePDF |
| `online` | a surface byte, a status, length flags, a header block, then a body | the HTTP response handling of the online clients: the fetcher (redirects, size and truncation limits, the RFC 9111 cache with validators and stale-on-error), the time-stamp, OCSP, CRL and issuer-certificate interpretation of what it returns, and the Cache-Control, HTTP-date and recorded-exchange parsers; nothing may throw |
| `verify` | a case byte, then a signature or a public key | the verify-only managed RSA (PKCS#1 v1.5, PSS) and ECDSA (P-256 and Brainpool, DER and fixed-width) verifiers, and their public-key validation |

Only the library's typed exceptions (and `OperationCanceledException`) may come out of a target. Any other exception, a hang (`-timeout`) or a memory blow-up (`-rss_limit_mb`) is a finding.

## Running

    export ONECRYPTO_FUZZ_TOOLS=/path/to/tools     # holds fuzz/libfuzzer-dotnet and sharpfuzz/sharpfuzz
    export ONECRYPTO_FUZZ_WORK=/path/to/workdir    # builds, corpora, findings; must be outside the checkout
    fuzz/run.sh cms 600                            # fuzz the CMS target for 10 minutes
    fuzz/run.sh replay cms some-input...           # run saved inputs once, without libFuzzer

`run.sh` builds the harness in release mode into `$ONECRYPTO_FUZZ_WORK/bin`, writes seeds into `$ONECRYPTO_FUZZ_WORK/corpus/<target>/`, instruments the library, and runs libFuzzer. Findings land in `$ONECRYPTO_FUZZ_WORK/findings/<target>/`. Per-input timeout and memory limit: `FUZZ_TIMEOUT` (10 s) and `FUZZ_RSS_MB` (1024). Extra arguments after the corpus directory go to libFuzzer. Run one fuzz process at a time.

The tools:

* `libfuzzer-dotnet`: the C++ host from the SharpFuzz project, compiled with `clang++ -fsanitize=fuzzer`.
* `sharpfuzz`: `dotnet tool install SharpFuzz.CommandLine --tool-path <dir>/sharpfuzz`.

Reading the output: `ft` (features) is the number to watch. The host's own `cov` stays small because only the .NET side is instrumented.

Without a libFuzzer host the executable has local modes, run as `dotnet OneCrypto.Fuzz.dll <mode>`: `mutate <target> <seconds> <seed>...` (random mutation in process; a crashing input is saved under `$ONECRYPTO_FUZZ_WORK/findings/mutate`), `replay` and `seeds`.

## Adding a target

1. Write `Run(ReadOnlySpan<byte> data)` that lets only the library's typed exceptions escape.
2. Add one line to `Targets` in `Program.cs`, one `case` in `run.sh` with its maximum input length, and its seeds to `SeedsFor`.
