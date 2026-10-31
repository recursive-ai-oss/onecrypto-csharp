# OneCrypto

Cryptography (not cryptocurrency) for .NET: message formats, certificates and the primitives the platform lacks, written from the specifications on the base class library alone. OneCrypto is unaffiliated with other products named OneCrypto.

**Status: preview (0.1), not yet independently audited.** The API may still change between previews. What is tested, against what, and where the library deviates is in [docs/conformance.md](docs/conformance.md); behaviour is specified in [docs/](docs/README.md).

```csharp
using RecursiveAI.OneCrypto;

using LoadedItems file = Crypto.Load("server.pfx", _ => password);   // any key or certificate file
```

## Packages

All packages share one version.

| Package | Contents | Status |
|---|---|---|
| `RecursiveAI.OneCrypto` | ASN.1 and PEM, X.509/CSR/CRL/OCSP, CMS, RFC 3161, PKCS#8/#12, OpenSSH keys, `CryptoPolicy`, key interfaces with two-phase signing, CA/TSA/OCSP-responder handlers, `Crypto.Load`, the primitives the platform lacks (Ed25519/Ed448, X25519/X448, OCB, EAX, AES-KW, Argon2, scrypt, bcrypt-pbkdf, Camellia, legacy decrypt-only ciphers); path validation as a preview. Depends on nothing but the base class library | preview |
| `RecursiveAI.OneCrypto.OpenPgp` | OpenPGP (RFC 9580, RFC 4880, LibrePGP) | planned |
| `RecursiveAI.OneCrypto.Online` | network clients behind a pluggable, guarded transport | planned |
| `RecursiveAI.OneCrypto.Keys` | PKCS#11, gpg-agent and ssh-agent key backends | planned |
| `RecursiveAI.OneCrypto.AdES` | CAdES, XAdES, XML-DSig, ASiC and ETSI validation | planned |
| `RecursiveAI.OneCrypto.Files` | age, minisign, signify, SSHSIG, Sigstore bundle verification | planned |
| `RecursiveAI.OneCrypto.Pdf` | PAdES and PDF signature validation on OnePDF | planned |
| `RecursiveAI.OneCrypto.AzureKeyVault`, `.AwsKms`, `.GoogleKms` | cloud key backends | planned |
| `onecrypto` (dotnet tool) | `sop`, inspection and convenience verbs | planned |

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
