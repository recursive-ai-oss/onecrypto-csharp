# RecursiveAI.OneCrypto.Online

Network clients for OneCrypto, the cryptography (not cryptocurrency) library for .NET: RFC 3161 time-stamping, OCSP (RFC 6960, with the RFC 5019 GET form), CRL and delta-CRL fetching, and issuer certificates from the authority information access extension, plus issuer and revocation sources for the OneCrypto path validator. It is unaffiliated with other products named OneCrypto.

Nothing fetches unless the call asks. The transport is pluggable and guarded by default: only `http` and `https`, no loopback, link-local or private addresses for URLs taken from certificates (checked at connect time), and limits on time, size and redirects. A record/replay transport makes network behaviour testable offline, and an RFC 9111 cache honours CRL and OCSP validity periods at the caller's reference time.

This is an early preview. It is not yet independently audited.

- Guide: <https://github.com/recursive-ai-oss/onecrypto-csharp/blob/v{VERSION}/docs/online.md>
- Source, issues and the full package list: <https://github.com/recursive-ai-oss/onecrypto-csharp>
- Changelog: <https://github.com/recursive-ai-oss/onecrypto-csharp/blob/v{VERSION}/CHANGELOG.md>
- Licence: MIT OR Apache-2.0, <https://github.com/recursive-ai-oss/onecrypto-csharp/blob/v{VERSION}/LICENSE-MIT> and <https://github.com/recursive-ai-oss/onecrypto-csharp/blob/v{VERSION}/LICENSE-APACHE>
