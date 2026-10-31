# Changelog

All notable changes are listed here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and versions follow [Semantic Versioning](https://semver.org/).

## [Unreleased]

### Added

- `RecursiveAI.OneCrypto.Validation`: the RFC 5280 path builder and validator (`PathValidator`), with per-rule reports for every certificate of every path tried, CRL (complete, delta, indirect) and OCSP revocation from supplied data, the past-time revocation model, name constraints, a bounded policy tree, work limits, an opt-in server-authentication profile with RFC 9525 host matching, optional async issuer and revocation sources, an OS root-store loader and an `X509Chain` side-by-side report. Behaviour and test results: `docs/validation.md`.
- X.509 models in the root namespace, immutable and lossless over the received octets: `Certificate` (with `X509Certificate2` conversion both ways), `CertificateSigningRequest`, `CertificateRevocationList` (complete, delta and indirect), `OcspRequest`, `OcspResponse`, `OcspBasicResponse` and read-only `AttributeCertificate`, with names (RFC 4514), general names, public keys and typed values for the RFC 5280 extensions; builders for certificates, requests, CRLs and OCSP messages that sign through `X509Signer`; structured signature results. See `docs/x509.md`.
- Repository skeleton: the package projects, the `onecrypto` tool shell, tests, fuzzing, benchmark, NativeAOT and browser-wasm smoke projects, and CI.
- Internal ASN.1 BER/DER reader and DER writer, BER-to-DER conversion, CMS SignedData reader and writer, signer verification and RFC 3161 request/response helpers, with their tests. None of it is public API yet.
