# RecursiveAI.OneCrypto.Pdf

PAdES for PDF on OnePDF, from OneCrypto, the cryptography (not cryptocurrency) library for .NET. It is unaffiliated with other products named OneCrypto.

- Sign PDFs at PAdES B-B, B-T, B-LT and B-LTA (ETSI EN 319 142-1) with RSA, ECDSA, Ed25519, Ed448 or ML-DSA (preview) keys, including keys held elsewhere, through OneCrypto's key interfaces and a two-step prepare/complete flow that can span processes.
- Add validation data (the document security store) and document time-stamps to signed files, and renew archive time-stamps.
- Validate PDF signatures with the OneCrypto path validator, including validation at a past time through time-stamps, on top of OnePDF's own byte-range and modification checks.
- Build a detached CMS signature from a precomputed digest with `SignedData.CreateDetachedFromDigest` (in the core package).

Nothing fetches unless the call asks: revocation data and time-stamps come from values or sources the caller supplies.

This is an early preview. It is not yet independently audited.

- Guide: <https://github.com/recursive-ai-oss/onecrypto-csharp/blob/v{VERSION}/docs/pdf.md>
- Source, issues and the full package list: <https://github.com/recursive-ai-oss/onecrypto-csharp>
- Changelog: <https://github.com/recursive-ai-oss/onecrypto-csharp/blob/v{VERSION}/CHANGELOG.md>
- Licence: MIT OR Apache-2.0, <https://github.com/recursive-ai-oss/onecrypto-csharp/blob/v{VERSION}/LICENSE-MIT> and <https://github.com/recursive-ai-oss/onecrypto-csharp/blob/v{VERSION}/LICENSE-APACHE>
