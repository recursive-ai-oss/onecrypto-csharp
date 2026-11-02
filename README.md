# OneCrypto

Cryptography (not cryptocurrency) for .NET: message formats, certificates and the primitives the platform lacks, written from the specifications on the base class library alone. OneCrypto is unaffiliated with other products named OneCrypto.

**Status: preview (0.3), not yet independently audited.** The API may still change between previews. What is tested, against what, and where the library deviates is in [docs/conformance.md](docs/conformance.md); behaviour is specified in [docs/](docs/README.md).

```csharp
using RecursiveAI.OneCrypto;

using LoadedItems file = Crypto.Load("server.pfx", _ => password);   // any key or certificate file
```

## Packages

All packages share one version.

| Package | Contents | Status |
|---|---|---|
| `RecursiveAI.OneCrypto` | ASN.1 and PEM, X.509/CSR/CRL/OCSP, CMS, RFC 3161, PKCS#8/#12, OpenSSH keys, `CryptoPolicy`, key interfaces with two-phase signing, CA/TSA/OCSP-responder handlers, `Crypto.Load`, the primitives the platform lacks (Ed25519/Ed448, X25519/X448, OCB, EAX, AES-KW, Argon2, scrypt, bcrypt-pbkdf, Camellia, legacy decrypt-only ciphers); path validation as a preview. Depends on nothing but the base class library | preview |
| `RecursiveAI.OneCrypto.OpenPgp` | OpenPGP: RFC 9580 version 6 and 4, RFC 9980 post-quantum algorithms, LibrePGP read (written only for recipients that need it), version 3 read; messages, streaming, key management, GnuPG home and cert-d, trust models, WKD, HKP, VKS and Autocrypt | preview |
| `RecursiveAI.OneCrypto.Online` | RFC 3161, OCSP, CRL and AIA clients over a pluggable, guarded transport with a cache and record/replay; sources for the path validator. Nothing is fetched unless a call asks | preview |
| `RecursiveAI.OneCrypto.Keys` | PKCS#11, gpg-agent and ssh-agent key backends | planned |
| `RecursiveAI.OneCrypto.AdES` | CAdES, XAdES, XML-DSig, ASiC and ETSI validation | planned |
| `RecursiveAI.OneCrypto.Files` | age, minisign, signify, SSHSIG, Sigstore bundle verification | planned |
| `RecursiveAI.OneCrypto.Pdf` | PAdES B-B to B-LTA signing, augmentation and verification on OnePDF, with OneCrypto keys, CMS, time-stamps and path validation | preview |
| `RecursiveAI.OneCrypto.AzureKeyVault`, `.AwsKms`, `.GoogleKms` | cloud key backends | planned |
| `onecrypto` (dotnet tool, package `RecursiveAI.OneCrypto.Cli`) | `sop` and `sopv` (the Stateless OpenPGP CLI), inspection and convenience verbs | preview |

## Building

The repository pins its SDK in `global.json` (.NET 10).

    dotnet build
    dotnet test

Build output goes to `$ONECRYPTO_ARTIFACTS` when that variable is set, otherwise to `artifacts/` in the checkout.

Other projects: `tests/AotSmoke` (NativeAOT publish and run), `tests/WasmSmoke` (browser-wasm, needs the `wasm-tools` workload; see its `run.sh`), `fuzz/` (SharpFuzz targets under libFuzzer, see `fuzz/README.md`), `bench/` (BenchmarkDotNet).

## Clean-room rule

OneCrypto is written from published specifications, standards and test vectors. Other implementations are used only as black-box programs to compare behaviour; their source is not read. Third-party test material and its terms are listed in `THIRD-PARTY-NOTICES.md`.

## Licence

MIT OR Apache-2.0, at your option. See `LICENSE-MIT` and `LICENSE-APACHE`. Copyright (c) Recursive AI, LLC.
