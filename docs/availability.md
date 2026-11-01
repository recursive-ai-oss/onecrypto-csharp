# Platform availability

What each algorithm resolves to on each platform. The library asks the platform's cryptography first. Where the platform lacks
an algorithm and the library has a narrow managed fallback, the call succeeds through the fallback. Otherwise it throws
`AlgorithmNotSupportedException`, which names the algorithm, the platform (operating system, architecture, runtime, and the
provider fact that decided it, such as the loaded OpenSSL version) and the reason.

**Provided by**

- **platform**: the .NET base class library, backed by the operating system's cryptography.
- **managed fallback**: the library's own code, used because the platform has no implementation.
- **not supported**: the platform has none and the library has no fallback.

## Which fallbacks exist, and why only those

- **SHA-3 and SHAKE** (FIPS 202) and **ChaCha20-Poly1305** (RFC 8439): constant time by construction. The platform has no
  SHA3-224 anywhere, so SHA3-224 is always the managed Keccak.
- **RSA verification** (PKCS#1 v1.5 and PSS, RFC 8017 section 8) and **ECDSA verification** (P-256, P-384, P-521 and the
  brainpoolP256r1, P384r1, P512r1 curves of RFC 5639; FIPS 186-5 section 6.4.2): public-key operations on public data only. The
  managed verifier is also used for RSA-PSS parameter sets the platform cannot express (a salt length other than the digest size,
  or a mask-function hash that differs from the message hash) and for PKCS#1 signatures over SHA-3 digests.
- **No fallback ever** for signing, decryption, key agreement or key generation of RSA, ECDSA or ECDH, for AES, and for ML-KEM,
  ML-DSA and SLH-DSA. These report `AlgorithmNotSupportedException` where the platform lacks them.

The browser has hashes and HMAC only: parsing, inspecting and verifying work there through the fallbacks, and everything else
reports `AlgorithmNotSupportedException`.

## Keeping the table honest

Each section below is generated from the dispatch code by the test `AvailabilityTests`, which fails when the section for the
platform it runs on differs from what the code reports. To update a section after a deliberate change, run that test on the
platform with `ONECRYPTO_AVAILABILITY_UPDATE=1`.

## Platforms

<!-- platform: linux-x64-openssl-3.0 -->
### linux-x64-openssl-3.0

| Algorithm | Provided by | Note |
| --- | --- | --- |
| SHA3-224 | managed fallback | the platform has no SHA3-224 at all |
| SHA3-256 | platform |  |
| SHA3-384 | platform |  |
| SHA3-512 | platform |  |
| SHAKE128 | platform |  |
| SHAKE256 | platform |  |
| ChaCha20-Poly1305 | platform |  |
| RSA verify (PKCS#1 v1.5, PSS) | platform | verify-only managed fallback where the platform cannot |
| ECDSA verify P-256, P-384, P-521 | platform | verify-only managed fallback where the platform cannot |
| ECDSA verify brainpoolP256r1 | platform | verify-only managed fallback where the platform cannot |
| ECDSA verify brainpoolP384r1 | platform | verify-only managed fallback where the platform cannot |
| ECDSA verify brainpoolP512r1 | platform | verify-only managed fallback where the platform cannot |
| AES (ECB, CBC, GCM), and OCB, EAX and key wrap over it | platform |  |
| AES-GCM (CMS AuthEnvelopedData, PKCS #8 and OpenSSH keys) | platform |  |
| AES-CCM (CMS AuthEnvelopedData when asked for) | platform |  |
| RSA sign, decrypt | platform | no fallback: private-key operations are never done in managed code |
| ECDSA, ECDH sign and agree | platform | no fallback: private-key operations are never done in managed code |
| ML-KEM | not supported | no fallback |
| ML-DSA | not supported | no fallback |
| SLH-DSA | not supported | no fallback; the platform's API is a preview |
<!-- end -->

<!-- platform: linux-x64-openssl-3.5 -->
### linux-x64-openssl-3.5

| Algorithm | Provided by | Note |
| --- | --- | --- |
| SHA3-224 | managed fallback | the platform has no SHA3-224 at all |
| SHA3-256 | platform |  |
| SHA3-384 | platform |  |
| SHA3-512 | platform |  |
| SHAKE128 | platform |  |
| SHAKE256 | platform |  |
| ChaCha20-Poly1305 | platform |  |
| RSA verify (PKCS#1 v1.5, PSS) | platform | verify-only managed fallback where the platform cannot |
| ECDSA verify P-256, P-384, P-521 | platform | verify-only managed fallback where the platform cannot |
| ECDSA verify brainpoolP256r1 | platform | verify-only managed fallback where the platform cannot |
| ECDSA verify brainpoolP384r1 | platform | verify-only managed fallback where the platform cannot |
| ECDSA verify brainpoolP512r1 | platform | verify-only managed fallback where the platform cannot |
| AES (ECB, CBC, GCM), and OCB, EAX and key wrap over it | platform |  |
| AES-GCM (CMS AuthEnvelopedData, PKCS #8 and OpenSSH keys) | platform |  |
| AES-CCM (CMS AuthEnvelopedData when asked for) | platform |  |
| RSA sign, decrypt | platform | no fallback: private-key operations are never done in managed code |
| ECDSA, ECDH sign and agree | platform | no fallback: private-key operations are never done in managed code |
| ML-KEM | platform | no fallback |
| ML-DSA | platform | no fallback |
| SLH-DSA | platform | no fallback; the platform's API is a preview |
<!-- end -->

<!-- platform: win-x64 -->
### win-x64

| Algorithm | Provided by | Note |
| --- | --- | --- |
| SHA3-224 | managed fallback | the platform has no SHA3-224 at all |
| SHA3-256 | platform |  |
| SHA3-384 | platform |  |
| SHA3-512 | platform |  |
| SHAKE128 | platform |  |
| SHAKE256 | platform |  |
| ChaCha20-Poly1305 | platform |  |
| RSA verify (PKCS#1 v1.5, PSS) | platform | verify-only managed fallback where the platform cannot |
| ECDSA verify P-256, P-384, P-521 | platform | verify-only managed fallback where the platform cannot |
| ECDSA verify brainpoolP256r1 | platform | verify-only managed fallback where the platform cannot |
| ECDSA verify brainpoolP384r1 | platform | verify-only managed fallback where the platform cannot |
| ECDSA verify brainpoolP512r1 | platform | verify-only managed fallback where the platform cannot |
| AES (ECB, CBC, GCM), and OCB, EAX and key wrap over it | platform |  |
| AES-GCM (CMS AuthEnvelopedData, PKCS #8 and OpenSSH keys) | platform |  |
| AES-CCM (CMS AuthEnvelopedData when asked for) | platform |  |
| RSA sign, decrypt | platform | no fallback: private-key operations are never done in managed code |
| ECDSA, ECDH sign and agree | platform | no fallback: private-key operations are never done in managed code |
| ML-KEM | platform | no fallback |
| ML-DSA | platform | no fallback |
| SLH-DSA | platform | no fallback; the platform's API is a preview |
<!-- end -->

<!-- platform: osx-arm64 -->
### osx-arm64

| Algorithm | Provided by | Note |
| --- | --- | --- |
| SHA3-224 | managed fallback | the platform has no SHA3-224 at all |
| SHA3-256 | managed fallback |  |
| SHA3-384 | managed fallback |  |
| SHA3-512 | managed fallback |  |
| SHAKE128 | managed fallback |  |
| SHAKE256 | managed fallback |  |
| ChaCha20-Poly1305 | platform |  |
| RSA verify (PKCS#1 v1.5, PSS) | platform | verify-only managed fallback where the platform cannot |
| ECDSA verify P-256, P-384, P-521 | platform | verify-only managed fallback where the platform cannot |
| ECDSA verify brainpoolP256r1 | managed fallback | verify-only managed fallback where the platform cannot |
| ECDSA verify brainpoolP384r1 | managed fallback | verify-only managed fallback where the platform cannot |
| ECDSA verify brainpoolP512r1 | managed fallback | verify-only managed fallback where the platform cannot |
| AES (ECB, CBC, GCM), and OCB, EAX and key wrap over it | platform |  |
| AES-GCM (CMS AuthEnvelopedData, PKCS #8 and OpenSSH keys) | platform |  |
| AES-CCM (CMS AuthEnvelopedData when asked for) | not supported |  |
| RSA sign, decrypt | platform | no fallback: private-key operations are never done in managed code |
| ECDSA, ECDH sign and agree | platform | no fallback: private-key operations are never done in managed code |
| ML-KEM | not supported | no fallback |
| ML-DSA | not supported | no fallback |
| SLH-DSA | not supported | no fallback; the platform's API is a preview |
<!-- end -->

<!-- platform: browser-wasm -->
### browser-wasm

| Algorithm | Provided by | Note |
| --- | --- | --- |
| SHA3-224 | managed fallback | the platform has no SHA3-224 at all |
| SHA3-256 | managed fallback |  |
| SHA3-384 | managed fallback |  |
| SHA3-512 | managed fallback |  |
| SHAKE128 | managed fallback |  |
| SHAKE256 | managed fallback |  |
| ChaCha20-Poly1305 | managed fallback |  |
| RSA verify (PKCS#1 v1.5, PSS) | managed fallback | verify-only managed fallback where the platform cannot |
| ECDSA verify P-256, P-384, P-521 | managed fallback | verify-only managed fallback where the platform cannot |
| ECDSA verify brainpoolP256r1 | managed fallback | verify-only managed fallback where the platform cannot |
| ECDSA verify brainpoolP384r1 | managed fallback | verify-only managed fallback where the platform cannot |
| ECDSA verify brainpoolP512r1 | managed fallback | verify-only managed fallback where the platform cannot |
| AES (ECB, CBC, GCM), and OCB, EAX and key wrap over it | not supported |  |
| AES-GCM (CMS AuthEnvelopedData, PKCS #8 and OpenSSH keys) | not supported |  |
| AES-CCM (CMS AuthEnvelopedData when asked for) | not supported |  |
| RSA sign, decrypt | not supported | no fallback: private-key operations are never done in managed code |
| ECDSA, ECDH sign and agree | not supported | no fallback: private-key operations are never done in managed code |
| ML-KEM | not supported | no fallback |
| ML-DSA | not supported | no fallback |
| SLH-DSA | not supported | no fallback; the platform's API is a preview |
<!-- end -->
