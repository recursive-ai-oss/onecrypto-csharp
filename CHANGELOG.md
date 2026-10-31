# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Changed

- The path validator takes a `CryptoPolicy` (`ValidationOptions.Policy`, default `Standard`) in place of the algorithm-check hook, and reports each algorithm decision with its policy rule id (`RuleResult.PolicyRule`). `CryptoPolicy.Permissive` accepts everything the library can verify. SHA-1 certificate signatures are now flagged from 2011 and rejected from 2031 under `Standard` (they were rejected from 2017), and RSA keys under 2048 bits are flagged, not rejected, from 2014; `Strict` refuses both.
- Required revocation with no usable data now makes the verdict `Indeterminate` by default (`UnknownRevocationIsFatal` defaults to true).
- When a work limit stops path building before any path validates, the verdict is `Indeterminate`, not `Invalid`; candidates that cannot issue are tried last.

### Fixed

- A CRL signer is validated to the trust anchor of the certificate's own path (RFC 5280 §6.3.3 (f)); a listed entry outside the CRL's reason scope still counts as revoked; a CRL with an unknown critical entry extension is unusable; `SmtpUTF8Mailbox` is constrained as rfc822Name; trailing dots and percent-encoding in URI hosts no longer escape name constraints; the required extended key usage applies to a target that is a trust anchor; `*.` wildcards match A-label hosts.

### Added

- `SignedDataVerifyOptions.Chain`: each signer and countersigner of a SignedData is validated by the path validator, with the message's certificates, CRLs and OCSP responses as untrusted input; `SignerReport.Chain` holds the validator's report and the `chain` check summarises it.
- `Crypto.Load`: one call that takes bytes, a stream or a path and returns what a key or certificate file holds, typed (`LoadedItems`): certificates and chains, CRLs, certification requests, OCSP responses, public keys, private keys as usable `ISigningKey`/`IDecryptionKey`/`IAgreementKey`, PKCS#7 certificate bags, PKCS#12 contents, OpenSSH keys, certificates and `authorized_keys`, from PEM or DER by a fixed decision table. A password callback is asked at most once per distinct secret. Bad input raises `CryptoLoadException` (or `Crypto.TryLoad`) with the formats considered. See `docs/load.md`.
- `RecursiveAI.OneCrypto.Validation`: the RFC 5280 path builder and validator (`PathValidator`), with per-rule reports for every certificate of every path tried, CRL (complete, delta, indirect) and OCSP revocation from supplied data, the past-time revocation model, name constraints, a bounded policy tree, work limits, an opt-in server-authentication profile with RFC 9525 host matching, optional async issuer and revocation sources, an OS root-store loader and an `X509Chain` side-by-side report. Behaviour and test results: `docs/validation.md`.
- `CryptoPolicy` (`Standard`, `Strict`, dated SHA-1/MD5/RSA rules, explicit reference time, decisions with rule ids and references); key interfaces (`ISigningKey`, `IDecryptionKey`, `IAgreementKey`, `IRsaKey`) with in-memory, library-curve and operating-system backends (`PrivateKey`); `SignatureSpec`; serialisable two-phase signing (`PreparedSignature`) with two-phase certificates, requests and revocation lists. RSASSA-PSS certificates with any salt length or MGF1 hash now verify.
- X.509 models in the root namespace, immutable and lossless over the received octets: `Certificate` (with `X509Certificate2` conversion both ways), `CertificateSigningRequest`, `CertificateRevocationList` (complete, delta and indirect), `OcspRequest`, `OcspResponse`, `OcspBasicResponse` and read-only `AttributeCertificate`, with names (RFC 4514), general names, public keys and typed values for the RFC 5280 extensions; builders for certificates, requests, CRLs and OCSP messages that sign through `X509Signer`; structured signature results. See `docs/x509.md`.
- Repository skeleton: the package projects, the `onecrypto` tool shell, tests, fuzzing, benchmark, NativeAOT and browser-wasm smoke projects, and CI.
- Internal ASN.1 BER/DER reader and DER writer, BER-to-DER conversion, CMS SignedData reader and writer, signer verification and RFC 3161 request/response helpers, with their tests. None of it is public API yet.
